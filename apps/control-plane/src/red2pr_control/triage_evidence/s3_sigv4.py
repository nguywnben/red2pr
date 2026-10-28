"""Pure-Python AWS Signature Version 4 (`AWS4-HMAC-SHA256`) signer & verifier for S3 REST (`U13`).

Implements standard S3 Signature Version 4 canonical request construction and HMAC key
derivation (`AWS4` + secret -> date -> region -> `s3` -> `aws4_request`) without adding
heavy external AWS SDK dependencies, preserving `ADR-037` outbound egress control.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import parse_qsl, quote, urlsplit

_AUTH_HEADER_RE = re.compile(
    r"^AWS4-HMAC-SHA256\s+"
    r"Credential=(?P<credential>[^,\s]+),\s*"
    r"SignedHeaders=(?P<signed_headers>[^,\s]+),\s*"
    r"Signature=(?P<signature>[0-9a-f]{64})$"
)


@dataclass(frozen=True, slots=True)
class S3Credentials:
    """S3-compatible object store access credentials and region."""

    access_key_id: str
    secret_access_key: str
    region: str = "us-east-1"
    session_token: str | None = None


def _hmac_sha256(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def derive_s3_signing_key(
    *,
    secret_access_key: str,
    datestamp: str,
    region: str,
    service: str = "s3",
) -> bytes:
    """Derive AWS4 signing key for `(datestamp, region, service)`."""
    k_date = _hmac_sha256(f"AWS4{secret_access_key}".encode(), datestamp)
    k_region = _hmac_sha256(k_date, region)
    k_service = _hmac_sha256(k_region, service)
    return _hmac_sha256(k_service, "aws4_request")


def canonicalize_s3_uri(raw_path: str) -> str:
    """URI-encode each S3 path segment per RFC 3986 while preserving `/` separators."""
    if not raw_path or raw_path == "/":
        return "/"
    segments = raw_path.split("/")
    return "/".join(quote(seg, safe="-_.~") for seg in segments)


def canonicalize_s3_query(raw_query: str | Sequence[tuple[str, str]]) -> str:
    """Sort and RFC 3986 encode query parameters for SigV4 canonical request."""
    if isinstance(raw_query, str):
        pairs = parse_qsl(raw_query, keep_blank_values=True)
    else:
        pairs = list(raw_query)
    encoded_pairs = [(quote(str(k), safe="-_.~"), quote(str(v), safe="-_.~")) for k, v in pairs]
    encoded_pairs.sort(key=lambda item: (item[0], item[1]))
    return "&".join(f"{k}={v}" for k, v in encoded_pairs)


def format_amz_timestamps(now: datetime) -> tuple[str, str]:
    """Return `(amz_date, datestamp)` formatted in UTC (`YYYYMMDDTHHMMSSZ`, `YYYYMMDD`)."""
    utc_dt = now.astimezone(UTC)
    return utc_dt.strftime("%Y%m%dT%H%M%SZ"), utc_dt.strftime("%Y%m%d")


def compute_host_header(scheme: str, host: str, port: int | None) -> str:
    """Format canonical HTTP `Host` header omitting default ports 80/443."""
    clean_host = host.strip().lower()
    if ":" in clean_host and not clean_host.startswith("["):
        clean_host = f"[{clean_host}]"
    default_port = 443 if scheme.lower() == "https" else 80
    if port is None or port == default_port:
        return clean_host
    return f"{clean_host}:{port}"


def sign_s3_v4_headers(
    *,
    method: str,
    url: str,
    credentials: S3Credentials,
    body: bytes = b"",
    extra_headers: Mapping[str, str] | None = None,
    now: datetime | None = None,
) -> dict[str, str]:
    """Sign an HTTP request for S3 / MinIO using `AWS4-HMAC-SHA256`."""
    ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
    amz_date, datestamp = format_amz_timestamps(ref_now)
    payload_hash = hashlib.sha256(body).hexdigest()

    parsed = urlsplit(url)
    host_val = compute_host_header(
        parsed.scheme or "https",
        parsed.hostname or "",
        parsed.port,
    )

    headers_out: dict[str, str] = {}
    if extra_headers:
        for hk, hv in extra_headers.items():
            headers_out[hk] = hv

    headers_out["Host"] = host_val
    headers_out["x-amz-date"] = amz_date
    headers_out["x-amz-content-sha256"] = payload_hash
    if credentials.session_token:
        headers_out["x-amz-security-token"] = credentials.session_token

    canonical_map: dict[str, str] = {}
    for hk, hv in headers_out.items():
        lk = hk.strip().lower()
        if lk == "host" or lk == "content-type" or lk.startswith("x-amz-"):
            canonical_map[lk] = " ".join(hv.strip().split())

    sorted_header_names = sorted(canonical_map.keys())
    canonical_headers = "".join(f"{k}:{canonical_map[k]}\n" for k in sorted_header_names)
    signed_headers = ";".join(sorted_header_names)

    canonical_request = "\n".join(
        [
            method.upper().strip(),
            canonicalize_s3_uri(parsed.path or "/"),
            canonicalize_s3_query(parsed.query),
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )
    credential_scope = f"{datestamp}/{credentials.region}/s3/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    signing_key = derive_s3_signing_key(
        secret_access_key=credentials.secret_access_key,
        datestamp=datestamp,
        region=credentials.region,
    )
    signature = hmac.new(
        signing_key,
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    headers_out["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={credentials.access_key_id}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return headers_out


def verify_s3_v4_request(
    *,
    method: str,
    raw_path: str,
    raw_query: str,
    headers: Mapping[str, str],
    body: bytes,
    credentials: S3Credentials,
) -> tuple[bool, str]:
    """Verify an incoming `AWS4-HMAC-SHA256` signed S3 request in constant time."""
    lower_headers = {k.strip().lower(): " ".join(v.strip().split()) for k, v in headers.items()}
    auth = lower_headers.get("authorization", "")
    match = _AUTH_HEADER_RE.match(auth)
    if match is None:
        return False, "missing_or_malformed_authorization"

    cred_parts = match.group("credential").split("/")
    if len(cred_parts) != 5:
        return False, "invalid_credential_scope"
    access_key, datestamp, region, service, term = cred_parts
    if (
        not hmac.compare_digest(access_key, credentials.access_key_id)
        or region != credentials.region
        or service != "s3"
        or term != "aws4_request"
    ):
        return False, "credential_scope_mismatch"

    amz_date = lower_headers.get("x-amz-date", "")
    if not amz_date.startswith(datestamp):
        return False, "amz_date_mismatch"

    claimed_sha = lower_headers.get("x-amz-content-sha256", "")
    actual_sha = hashlib.sha256(body).hexdigest()
    if not hmac.compare_digest(claimed_sha.lower(), actual_sha):
        return False, "payload_sha256_mismatch"

    signed_header_list = [h.strip() for h in match.group("signed_headers").split(";") if h.strip()]
    if "host" not in signed_header_list or "x-amz-date" not in signed_header_list:
        return False, "missing_required_signed_headers"

    for h_name in signed_header_list:
        if h_name not in lower_headers:
            return False, f"missing_signed_header:{h_name}"

    canonical_headers = "".join(f"{h}:{lower_headers[h]}\n" for h in signed_header_list)
    signed_headers_str = ";".join(signed_header_list)
    canonical_request = "\n".join(
        [
            method.upper().strip(),
            canonicalize_s3_uri(raw_path or "/"),
            canonicalize_s3_query(raw_query),
            canonical_headers,
            signed_headers_str,
            actual_sha,
        ]
    )
    credential_scope = f"{datestamp}/{region}/s3/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    signing_key = derive_s3_signing_key(
        secret_access_key=credentials.secret_access_key,
        datestamp=datestamp,
        region=region,
    )
    expected_sig = hmac.new(
        signing_key,
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, match.group("signature")):
        return False, "signature_mismatch"
    return True, "ok"
