"""ADR-037 DNS-pinning outbound egress policy engine, transport, and HTTP client.

Enforces `SEC-014` and `SEC-033` across all control-plane Z1/Z2 outbound HTTP adapters:
- Denies loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`),
  cloud metadata (`169.254.169.254`, `[fd00:ec2::254]`), multicast, unspecified, and
  embedded-IPv4 transition addresses (`::ffff:0:0/96`, `2002::/16`, `2001::/32`,
  `64:ff9b::/96`, `64:ff9b:1::/48`) unconditionally.
- Denies private/internal ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
  `100.64.0.0/10`, `fc00::/7`) and cleartext `http://` by default unless an active
  instance-owner `RegisteredEndpointRule` matches the exact `(adapter, scheme, host, port)`
  and EVERY resolved IP falls inside `rule.cidrs`.
- Resolves `A`/`AAAA` records ONCE per connection, validates every returned IP before
  opening a socket, and pins the validated literal IP at the `httpcore` TCP layer while
  preserving original `Host` header and TLS SNI (`server_hostname`) to defeat DNS rebinding.
- Disables ambient proxy/TLS env overrides (`trust_env=False`), enforces `TLS >= 1.2` with
  `CERT_REQUIRED` + `check_hostname = True` (including custom `ca_ref` bundles), and
  re-validates every HTTP redirect hop (`max_redirects = 3`), stripping credential headers
  on any cross-origin redirect.
"""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import re
import socket
import ssl
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol

import httpcore
import httpx

from py_contracts.integrations import EgressAdapterKind, EndpointScheme
from red2pr_control.core.errors import ForbiddenError
from red2pr_control.core.logging import current_correlation_id, get_structured_logger

logger = get_structured_logger("red2pr_control.core.egress")

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_NUMERIC_OR_HEX_LABEL_RE = re.compile(r"^(?:0x[0-9a-f]+|0[0-7]+|\d+)$")

_PERMANENTLY_FORBIDDEN_V4: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("192.0.0.0/24"),
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.18.0.0/15"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("240.0.0.0/4"),
)

_PERMANENTLY_FORBIDDEN_V6: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.IPv6Network("::/128"),
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fd00:ec2::254/128"),
    ipaddress.IPv6Network("fe80::/10"),
    ipaddress.IPv6Network("ff00::/8"),
    ipaddress.IPv6Network("2001:db8::/32"),
)

_NAT64_PREFIXES: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.IPv6Network("64:ff9b::/96"),
    ipaddress.IPv6Network("64:ff9b:1::/48"),
)

_PRIVATE_OR_SHARED_V4: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("100.64.0.0/10"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)

_PRIVATE_ULA_V6 = ipaddress.IPv6Network("fc00::/7")

_CREDENTIAL_HEADER_NAMES: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-gitlab-token",
        "private-token",
        "x-hub-signature",
        "x-hub-signature-256",
        "x-telegram-bot-api-secret-token",
        "x-csrf-token",
    }
)
_CREDENTIAL_HEADER_SUFFIXES: tuple[str, ...] = (
    "-token",
    "-secret",
    "-key",
    "-signature",
)
_REDIRECT_STATUS_CODES: frozenset[int] = frozenset({301, 302, 303, 307, 308})


class EgressBlockedError(ForbiddenError):
    """Raised when an outbound HTTP target violates ADR-037 / SEC-014 / SEC-033 policy."""

    def __init__(
        self,
        *,
        code: str,
        detail: str,
        adapter: EgressAdapterKind,
        target_url: str,
        resolved_ips: tuple[str, ...] = (),
    ) -> None:
        super().__init__(code=code, detail=detail)
        self.adapter = adapter
        self.target_url = target_url
        self.resolved_ips = resolved_ips


@dataclass(frozen=True, slots=True)
class EgressAuditEvent:
    """Structured telemetry/audit event emitted for outbound egress policy evaluations."""

    adapter: EgressAdapterKind
    scheme: str
    host: str
    port: int
    decision: Literal["allow", "deny"]
    reason_code: str
    resolved_ips: tuple[str, ...]
    correlation_id: str


EgressAuditSink = Callable[[EgressAuditEvent], Awaitable[None] | None]


@dataclass(frozen=True, slots=True)
class RegisteredEndpointRule:
    """Immutable runtime projection of an active `endpoint_registrations` row."""

    endpoint_id: str
    adapter: EgressAdapterKind
    scheme: EndpointScheme
    host: str
    port: int
    cidrs: tuple[IpNetwork, ...]
    ca_ref: str | None = None

    @classmethod
    def from_values(
        cls,
        *,
        endpoint_id: str,
        adapter: EgressAdapterKind,
        scheme: EndpointScheme,
        host: str,
        port: int,
        cidrs: Sequence[str],
        ca_ref: str | None = None,
    ) -> RegisteredEndpointRule:
        parsed_cidrs = tuple(ipaddress.ip_network(raw.strip(), strict=False) for raw in cidrs)
        if not parsed_cidrs:
            raise ValueError("RegisteredEndpointRule requires at least one CIDR")
        normalized_host = host.strip().lower().rstrip(".")
        if normalized_host.startswith("[") and normalized_host.endswith("]"):
            normalized_host = normalized_host[1:-1]
        return cls(
            endpoint_id=endpoint_id,
            adapter=adapter,
            scheme=scheme,
            host=normalized_host,
            port=port,
            cidrs=parsed_cidrs,
            ca_ref=ca_ref,
        )


class EndpointAllowlistProviderProtocol(Protocol):
    """Lookup contract for active owner-registered private endpoints."""

    async def find_active_rule(
        self,
        *,
        adapter: EgressAdapterKind,
        scheme: EndpointScheme,
        host: str,
        port: int,
    ) -> RegisteredEndpointRule | None: ...


class InMemoryEndpointAllowlistProvider:
    """Deterministic in-memory endpoint allowlist provider for isolated tests or static config."""

    def __init__(self, rules: Sequence[RegisteredEndpointRule] = ()) -> None:
        self._rules: dict[
            tuple[EgressAdapterKind, EndpointScheme, str, int],
            RegisteredEndpointRule,
        ] = {}
        for rule in rules:
            self.upsert(rule)

    def upsert(self, rule: RegisteredEndpointRule) -> None:
        key = (rule.adapter, rule.scheme, rule.host.lower(), rule.port)
        self._rules[key] = rule

    def revoke(
        self,
        *,
        adapter: EgressAdapterKind,
        scheme: EndpointScheme,
        host: str,
        port: int,
    ) -> None:
        self._rules.pop((adapter, scheme, host.lower(), port), None)

    async def find_active_rule(
        self,
        *,
        adapter: EgressAdapterKind,
        scheme: EndpointScheme,
        host: str,
        port: int,
    ) -> RegisteredEndpointRule | None:
        return self._rules.get((adapter, scheme, host.lower(), port))


class DnsResolverProtocol(Protocol):
    """Async hostname -> numeric IP string resolver."""

    async def resolve(self, host: str, port: int) -> Sequence[str]: ...


class SystemAsyncDnsResolver:
    """Default async OS `getaddrinfo` resolver returning deduplicated numeric IPs."""

    async def resolve(self, host: str, port: int) -> Sequence[str]:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
        seen: dict[str, None] = {}
        for _family, _socktype, _proto, _canonname, sockaddr in infos:
            ip_text = str(sockaddr[0]).split("%", 1)[0]
            seen.setdefault(ip_text, None)
        return tuple(seen.keys())


class CaBundleResolverProtocol(Protocol):
    """Resolves opaque `ca_ref` handles to PEM-encoded CA trust bundle text."""

    async def resolve_ca_pem(self, ca_ref: str) -> str | None: ...


class InMemoryCaBundleResolver:
    """In-memory `ca_ref -> PEM` resolver."""

    def __init__(self, bundles: Mapping[str, str] | None = None) -> None:
        self._bundles: dict[str, str] = dict(bundles) if bundles is not None else {}

    def register(self, ca_ref: str, pem_bundle: str) -> None:
        self._bundles[ca_ref] = pem_bundle

    async def resolve_ca_pem(self, ca_ref: str) -> str | None:
        return self._bundles.get(ca_ref)


@dataclass(frozen=True, slots=True)
class PinnedEgressTarget:
    """Validated, DNS-pinned connection plan for a single outbound HTTP request."""

    adapter: EgressAdapterKind
    scheme: EndpointScheme
    host: str
    port: int
    pinned_ips: tuple[IpAddress, ...]
    ca_ref: str | None


def _extract_embedded_ipv4(ip_obj: IpAddress) -> ipaddress.IPv4Address | None:
    if not isinstance(ip_obj, ipaddress.IPv6Address):
        return None
    if ip_obj.ipv4_mapped is not None:
        return ip_obj.ipv4_mapped
    if ip_obj.sixtofour is not None:
        return ip_obj.sixtofour
    if ip_obj.teredo is not None:
        return ip_obj.teredo[1]
    if any(ip_obj in prefix for prefix in _NAT64_PREFIXES):
        return ipaddress.IPv4Address(int(ip_obj) & 0xFFFFFFFF)
    return None


def _is_permanently_forbidden_ip(ip_obj: IpAddress) -> bool:
    embedded_v4 = _extract_embedded_ipv4(ip_obj)
    if embedded_v4 is not None:
        return True
    if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
        return True
    if isinstance(ip_obj, ipaddress.IPv4Address):
        return any(ip_obj in net for net in _PERMANENTLY_FORBIDDEN_V4)
    return any(ip_obj in net for net in _PERMANENTLY_FORBIDDEN_V6)


def _is_private_or_non_global_ip(ip_obj: IpAddress) -> bool:
    if isinstance(ip_obj, ipaddress.IPv4Address):
        if any(ip_obj in net for net in _PRIVATE_OR_SHARED_V4):
            return True
        return not ip_obj.is_global
    if ip_obj in _PRIVATE_ULA_V6:
        return True
    return not ip_obj.is_global


def _ip_matches_rule_cidrs(ip_obj: IpAddress, cidrs: Sequence[IpNetwork]) -> bool:
    for cidr in cidrs:
        same_family = (
            isinstance(ip_obj, ipaddress.IPv4Address) and isinstance(cidr, ipaddress.IPv4Network)
        ) or (isinstance(ip_obj, ipaddress.IPv6Address) and isinstance(cidr, ipaddress.IPv6Network))
        if same_family and ip_obj in cidr:
            return True
    return False


def _effective_port(scheme: str, explicit_port: int | None) -> int:
    if explicit_port is not None:
        return explicit_port
    return 443 if scheme == "https" else 80


def _sanitize_url_for_log(url: httpx.URL) -> str:
    port_suffix = ""
    default_port = 443 if url.scheme == "https" else 80
    if url.port is not None and url.port != default_port:
        port_suffix = f":{url.port}"
    host_display = f"[{url.host}]" if ":" in url.host else url.host
    return f"{url.scheme}://{host_display}{port_suffix}{url.path or '/'}"


def _is_credential_header(header_name: str) -> bool:
    lowered = header_name.strip().lower()
    if lowered in _CREDENTIAL_HEADER_NAMES:
        return True
    return any(lowered.endswith(suffix) for suffix in _CREDENTIAL_HEADER_SUFFIXES)


class EgressPolicyEngine:
    """Evaluates outbound URLs and DNS answers against ADR-037 & SEC-033 rules."""

    def __init__(
        self,
        *,
        dns_resolver: DnsResolverProtocol | None = None,
        allowlist_provider: EndpointAllowlistProviderProtocol | None = None,
        audit_sink: EgressAuditSink | None = None,
    ) -> None:
        self._dns_resolver = dns_resolver if dns_resolver is not None else SystemAsyncDnsResolver()
        self._allowlist = (
            allowlist_provider
            if allowlist_provider is not None
            else InMemoryEndpointAllowlistProvider()
        )
        self._audit_sink = audit_sink

    async def _emit(
        self,
        *,
        adapter: EgressAdapterKind,
        scheme: str,
        host: str,
        port: int,
        decision: Literal["allow", "deny"],
        reason_code: str,
        resolved_ips: tuple[str, ...],
    ) -> None:
        corr_id = current_correlation_id()
        event = EgressAuditEvent(
            adapter=adapter,
            scheme=scheme,
            host=host,
            port=port,
            decision=decision,
            reason_code=reason_code,
            resolved_ips=resolved_ips,
            correlation_id=corr_id,
        )
        if decision == "deny":
            logger.warning(
                "Outbound egress blocked by ADR-037 policy",
                extra={
                    "event": "egress.denied",
                    "adapter": adapter,
                    "scheme": scheme,
                    "host": host,
                    "port": port,
                    "reason_code": reason_code,
                    "resolved_ips": list(resolved_ips),
                },
            )
        if self._audit_sink is not None:
            maybe_coro = self._audit_sink(event)
            if inspect.isawaitable(maybe_coro):
                await maybe_coro

    async def _deny(
        self,
        *,
        adapter: EgressAdapterKind,
        url: httpx.URL,
        code: str,
        detail: str,
        resolved_ips: tuple[str, ...] = (),
    ) -> EgressBlockedError:
        safe_url = _sanitize_url_for_log(url)
        port = _effective_port(url.scheme, url.port)
        await self._emit(
            adapter=adapter,
            scheme=url.scheme or "unknown",
            host=url.host or "unknown",
            port=port,
            decision="deny",
            reason_code=code,
            resolved_ips=resolved_ips,
        )
        return EgressBlockedError(
            code=code,
            detail=detail,
            adapter=adapter,
            target_url=safe_url,
            resolved_ips=resolved_ips,
        )

    async def evaluate_and_resolve(
        self,
        *,
        adapter: EgressAdapterKind,
        url: httpx.URL,
    ) -> PinnedEgressTarget:
        scheme_raw = url.scheme.lower()
        if scheme_raw not in ("https", "http"):
            raise await self._deny(
                adapter=adapter,
                url=url,
                code="egress_scheme_denied",
                detail=(
                    f"Outbound scheme '{scheme_raw}' is forbidden; "
                    "only HTTPS (or registered HTTP) is allowed."
                ),
            )
        scheme: EndpointScheme = "https" if scheme_raw == "https" else "http"

        if url.username or url.password:
            raise await self._deny(
                adapter=adapter,
                url=url,
                code="egress_url_userinfo_denied",
                detail="Outbound URLs must not embed userinfo credentials.",
            )

        raw_host = url.host.strip().lower().rstrip(".")
        if raw_host.startswith("[") and raw_host.endswith("]"):
            raw_host = raw_host[1:-1]
        if not raw_host or len(raw_host) > 253:
            raise await self._deny(
                adapter=adapter,
                url=url,
                code="egress_host_invalid",
                detail="Outbound URL host is missing or exceeds 253 characters.",
            )

        port = _effective_port(scheme, url.port)
        if port < 1 or port > 65535:
            raise await self._deny(
                adapter=adapter,
                url=url,
                code="egress_host_invalid",
                detail="Outbound URL port must be in 1..65535.",
            )

        literal_ip: IpAddress | None = None
        normalized_host = raw_host
        try:
            literal_ip = ipaddress.ip_address(raw_host.split("%", 1)[0])
            normalized_host = literal_ip.compressed
        except ValueError:
            try:
                normalized_host = raw_host.encode("idna").decode("ascii").lower()
            except UnicodeError as exc:
                raise await self._deny(
                    adapter=adapter,
                    url=url,
                    code="egress_host_invalid",
                    detail="Outbound hostname failed IDNA normalization.",
                ) from exc
            labels = normalized_host.split(".")
            if all(_NUMERIC_OR_HEX_LABEL_RE.fullmatch(lbl) is not None for lbl in labels):
                raise await self._deny(
                    adapter=adapter,
                    url=url,
                    code="egress_host_invalid",
                    detail="Obfuscated numeric/octal/hex IPv4 hostnames are forbidden.",
                ) from None
            if not all(_DNS_LABEL_RE.fullmatch(lbl) is not None for lbl in labels):
                raise await self._deny(
                    adapter=adapter,
                    url=url,
                    code="egress_host_invalid",
                    detail="Outbound hostname contains invalid DNS characters.",
                ) from None

        rule = await self._allowlist.find_active_rule(
            adapter=adapter,
            scheme=scheme,
            host=normalized_host,
            port=port,
        )

        if scheme == "http" and rule is None:
            raise await self._deny(
                adapter=adapter,
                url=url,
                code="egress_cleartext_http_denied",
                detail=(
                    f"Cleartext HTTP egress to '{normalized_host}:{port}' is denied unless "
                    f"explicitly registered by the instance owner for adapter '{adapter}'."
                ),
            )

        if literal_ip is not None:
            candidate_ips: list[IpAddress] = [literal_ip]
        else:
            try:
                raw_answers = await self._dns_resolver.resolve(normalized_host, port)
            except OSError as exc:
                raise await self._deny(
                    adapter=adapter,
                    url=url,
                    code="egress_dns_failed",
                    detail=f"DNS resolution failed for outbound host '{normalized_host}'.",
                ) from exc

            if not raw_answers:
                raise await self._deny(
                    adapter=adapter,
                    url=url,
                    code="egress_dns_empty",
                    detail=f"DNS resolution returned zero addresses for '{normalized_host}'.",
                )

            candidate_ips = []
            for raw_ip in raw_answers:
                try:
                    parsed_ip = ipaddress.ip_address(raw_ip.strip().split("%", 1)[0])
                except ValueError as exc:
                    raise await self._deny(
                        adapter=adapter,
                        url=url,
                        code="egress_dns_failed",
                        detail=(
                            f"DNS resolver returned malformed IP address for '{normalized_host}'."
                        ),
                    ) from exc
                if parsed_ip not in candidate_ips:
                    candidate_ips.append(parsed_ip)

        resolved_ip_strings = tuple(ip.compressed for ip in candidate_ips)

        for ip_obj in candidate_ips:
            if _is_permanently_forbidden_ip(ip_obj):
                raise await self._deny(
                    adapter=adapter,
                    url=url,
                    code="egress_ip_permanently_denied",
                    detail=(
                        f"Outbound address '{ip_obj.compressed}' for host '{normalized_host}' "
                        "is in a permanently forbidden loopback, link-local, metadata, or "
                        "IPv6-transition range."
                    ),
                    resolved_ips=resolved_ip_strings,
                )

            if rule is not None:
                if not _ip_matches_rule_cidrs(ip_obj, rule.cidrs):
                    raise await self._deny(
                        adapter=adapter,
                        url=url,
                        code="egress_cidr_mismatch",
                        detail=(
                            f"Resolved IP '{ip_obj.compressed}' for registered endpoint "
                            f"'{normalized_host}:{port}' is outside registered CIDRs."
                        ),
                        resolved_ips=resolved_ip_strings,
                    )
            elif _is_private_or_non_global_ip(ip_obj):
                raise await self._deny(
                    adapter=adapter,
                    url=url,
                    code="egress_private_ip_denied",
                    detail=(
                        f"Resolved private/internal IP '{ip_obj.compressed}' for "
                        f"'{normalized_host}:{port}' is blocked because no active endpoint "
                        f"registration exists for adapter '{adapter}'."
                    ),
                    resolved_ips=resolved_ip_strings,
                )

        await self._emit(
            adapter=adapter,
            scheme=scheme,
            host=normalized_host,
            port=port,
            decision="allow",
            reason_code="registered_endpoint" if rule is not None else "public_https_unicast",
            resolved_ips=resolved_ip_strings,
        )
        return PinnedEgressTarget(
            adapter=adapter,
            scheme=scheme,
            host=normalized_host,
            port=port,
            pinned_ips=tuple(candidate_ips),
            ca_ref=rule.ca_ref if rule is not None else None,
        )


class _SinglePinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Per-connection network backend connecting ONLY to pre-validated literal IPs."""

    def __init__(
        self,
        *,
        delegate: httpcore.AsyncNetworkBackend,
        expected_port: int,
        pinned_ips: tuple[IpAddress, ...],
    ) -> None:
        self._delegate = delegate
        self._expected_port = expected_port
        self._pinned_ips = pinned_ips

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        _ = host  # Never pass hostname to OS socket layer; always connect to validated literal IP.
        if port != self._expected_port:
            raise RuntimeError(
                f"Pinned network backend port mismatch: expected {self._expected_port}, got {port}"
            )
        last_exc: Exception | None = None
        for ip_obj in self._pinned_ips:
            try:
                return await self._delegate.connect_tcp(
                    host=ip_obj.compressed,
                    port=port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except Exception as exc:
                last_exc = exc
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("No pinned IP addresses available for connection")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        _ = (path, timeout, socket_options)
        raise RuntimeError("Unix domain sockets are forbidden on outbound HTTP egress")

    async def sleep(self, seconds: float) -> None:
        await self._delegate.sleep(seconds)


class _OwnedConnectionResponseStream(httpx.AsyncByteStream):
    """Streams response chunks and closes both response stream and single-use connection."""

    def __init__(
        self,
        *,
        raw_stream: Any,
        connection: httpcore.AsyncHTTPConnection,
    ) -> None:
        self._raw_stream = raw_stream
        self._connection = connection
        self._closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        try:
            async for chunk in self._raw_stream:
                yield bytes(chunk)
        finally:
            await self.aclose()

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            aclose_fn = getattr(self._raw_stream, "aclose", None)
            if callable(aclose_fn):
                maybe_coro = aclose_fn()
                if inspect.isawaitable(maybe_coro):
                    await maybe_coro
        finally:
            await self._connection.aclose()


def _build_verified_ssl_context(custom_ca_pem: str | None) -> ssl.SSLContext:
    """Create a strict TLS >= 1.2 SSLContext with CERT_REQUIRED + hostname verification."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    if custom_ca_pem is not None:
        ctx.load_verify_locations(cadata=custom_ca_pem)
    return ctx


class EgressPinnedAsyncTransport(httpx.AsyncBaseTransport):
    """`httpx` async transport pinning validated DNS answers at socket creation (`SEC-033`)."""

    def __init__(
        self,
        *,
        adapter: EgressAdapterKind,
        policy_engine: EgressPolicyEngine,
        ca_bundle_resolver: CaBundleResolverProtocol | None = None,
        network_backend: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        self._adapter = adapter
        self._policy_engine = policy_engine
        self._ca_resolver = (
            ca_bundle_resolver if ca_bundle_resolver is not None else InMemoryCaBundleResolver()
        )
        self._network_backend = (
            network_backend if network_backend is not None else httpcore.AnyIOBackend()
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        pinned = await self._policy_engine.evaluate_and_resolve(
            adapter=self._adapter,
            url=request.url,
        )

        ssl_context: ssl.SSLContext | None = None
        if pinned.scheme == "https":
            custom_ca_pem: str | None = None
            if pinned.ca_ref is not None:
                custom_ca_pem = await self._ca_resolver.resolve_ca_pem(pinned.ca_ref)
                if not custom_ca_pem:
                    raise EgressBlockedError(
                        code="egress_ca_bundle_missing",
                        detail=(
                            f"Custom CA bundle '{pinned.ca_ref}' configured for "
                            f"'{pinned.host}:{pinned.port}' could not be resolved."
                        ),
                        adapter=self._adapter,
                        target_url=_sanitize_url_for_log(request.url),
                        resolved_ips=tuple(ip.compressed for ip in pinned.pinned_ips),
                    )
            ssl_context = _build_verified_ssl_context(custom_ca_pem)

        pinned_backend = _SinglePinnedNetworkBackend(
            delegate=self._network_backend,
            expected_port=pinned.port,
            pinned_ips=pinned.pinned_ips,
        )
        origin = httpcore.Origin(
            request.url.raw_scheme,
            request.url.raw_host,
            pinned.port,
        )
        connection = httpcore.AsyncHTTPConnection(
            origin=origin,
            ssl_context=ssl_context,
            keepalive_expiry=0.0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=pinned_backend,
        )

        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=pinned.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )

        try:
            core_response = await connection.handle_async_request(core_request)
        except EgressBlockedError:
            await connection.aclose()
            raise
        except httpcore.ConnectError as exc:
            await connection.aclose()
            raise httpx.ConnectError(str(exc), request=request) from exc
        except httpcore.ConnectTimeout as exc:
            await connection.aclose()
            raise httpx.ConnectTimeout(str(exc), request=request) from exc
        except httpcore.ReadTimeout as exc:
            await connection.aclose()
            raise httpx.ReadTimeout(str(exc), request=request) from exc
        except (httpcore.NetworkError, httpcore.ProtocolError, httpcore.TimeoutException) as exc:
            await connection.aclose()
            raise httpx.TransportError(str(exc), request=request) from exc
        except BaseException:
            await connection.aclose()
            raise

        return httpx.Response(
            status_code=core_response.status,
            headers=core_response.headers,
            stream=_OwnedConnectionResponseStream(
                raw_stream=core_response.stream,
                connection=connection,
            ),
            extensions=core_response.extensions,
        )

    async def aclose(self) -> None:
        return None


class EgressSafeHttpClient:
    """Adapter-scoped outbound HTTP client enforcing DNS pinning and safe redirects."""

    def __init__(
        self,
        *,
        adapter: EgressAdapterKind,
        policy_engine: EgressPolicyEngine,
        ca_bundle_resolver: CaBundleResolverProtocol | None = None,
        network_backend: httpcore.AsyncNetworkBackend | None = None,
        timeout_seconds: float = 15.0,
        max_redirects: int = 3,
    ) -> None:
        if max_redirects < 0 or max_redirects > 5:
            raise ValueError("max_redirects must be between 0 and 5")
        self._adapter = adapter
        self._policy_engine = policy_engine
        self._max_redirects = max_redirects
        self._transport = EgressPinnedAsyncTransport(
            adapter=adapter,
            policy_engine=policy_engine,
            ca_bundle_resolver=ca_bundle_resolver,
            network_backend=network_backend,
        )
        self._client = httpx.AsyncClient(
            transport=self._transport,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(timeout_seconds),
        )

    async def __aenter__(self) -> EgressSafeHttpClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str | httpx.URL,
        *,
        headers: Mapping[str, str] | None = None,
        content: bytes | str | None = None,
        json: Any = None,
    ) -> httpx.Response:
        current_method = method.upper()
        current_url = httpx.URL(url)
        current_headers: dict[str, str] = dict(headers) if headers is not None else {}
        current_content = content
        current_json = json

        for hop in range(self._max_redirects + 1):
            response = await self._client.request(
                current_method,
                current_url,
                headers=current_headers,
                content=current_content,
                json=current_json,
            )

            if response.status_code not in _REDIRECT_STATUS_CODES:
                return response

            location = response.headers.get("location")
            if not location:
                return response

            await response.aclose()

            if hop >= self._max_redirects:
                raise EgressBlockedError(
                    code="egress_redirect_limit_exceeded",
                    detail=(
                        f"Outbound request exceeded max_redirects={self._max_redirects} "
                        f"for adapter '{self._adapter}'."
                    ),
                    adapter=self._adapter,
                    target_url=_sanitize_url_for_log(current_url),
                )

            try:
                next_url = current_url.join(location.strip())
            except httpx.InvalidURL as exc:
                raise EgressBlockedError(
                    code="egress_redirect_invalid",
                    detail="Upstream response returned an invalid redirect Location URL.",
                    adapter=self._adapter,
                    target_url=_sanitize_url_for_log(current_url),
                ) from exc

            prev_origin = (
                current_url.scheme.lower(),
                current_url.host.lower(),
                _effective_port(current_url.scheme.lower(), current_url.port),
            )
            next_origin = (
                next_url.scheme.lower(),
                next_url.host.lower(),
                _effective_port(next_url.scheme.lower(), next_url.port),
            )
            if next_origin != prev_origin:
                current_headers = {
                    k: v for k, v in current_headers.items() if not _is_credential_header(k)
                }

            if response.status_code == 303 or (
                response.status_code in (301, 302) and current_method == "POST"
            ):
                current_method = "GET"
                current_content = None
                current_json = None
                current_headers = {
                    k: v
                    for k, v in current_headers.items()
                    if k.lower() not in ("content-length", "content-type")
                }

            current_url = next_url

        raise AssertionError("Unreachable redirect loop exit")
