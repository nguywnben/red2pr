"""TLS-only SMTP submission adapter with DNS pinning and safe multipart messages."""

from __future__ import annotations

import asyncio
import contextlib
import html
import json
import smtplib
import socket
import ssl
from email.message import EmailMessage
from email.utils import formataddr, parseaddr
from typing import Any

import httpx

from red2pr_control.core.egress import EgressPolicyEngine
from red2pr_control.notifications.dispatcher import (
    NotificationAdapterResult,
    NotificationSendRequest,
)

_MAX_MESSAGE_BYTES = 64 * 1024


def _safe_header(value: str, *, label: str, maximum: int) -> str:
    if not value or len(value) > maximum or any(char in value for char in "\r\n\x00"):
        raise ValueError(f"Invalid email {label} header.")
    return value


def _email_address(value: str, *, label: str) -> str:
    _safe_header(value, label=label, maximum=320)
    display, address = parseaddr(value)
    if not address or "@" not in address or "\r" in display or "\n" in display:
        raise ValueError(f"Invalid email {label} address.")
    return address


def build_email_message(
    *,
    sender: str,
    recipient: str,
    title: str,
    body: str,
    correlation_id: str,
    deep_link: str | None,
) -> EmailMessage:
    sender_addr = _email_address(sender, label="sender")
    recipient_addr = _email_address(recipient, label="recipient")
    subject = _safe_header(title, label="subject", maximum=180)
    corr = _safe_header(correlation_id, label="correlation", maximum=128)
    text = f"{subject}\n\n{body[:8192]}"
    if deep_link:
        text += f"\n\nOpen Red2PR: {_safe_header(deep_link, label='link', maximum=512)}"
    message = EmailMessage()
    message["From"] = formataddr(("Red2PR", sender_addr))
    message["To"] = recipient_addr
    message["Subject"] = subject
    message["X-Red2PR-Correlation-Id"] = corr
    message.set_content(text)
    escaped = html.escape(text, quote=True).replace("\n", "<br>\n")
    message.add_alternative(f"<!doctype html><html><body>{escaped}</body></html>", subtype="html")
    if len(message.as_bytes()) > _MAX_MESSAGE_BYTES:
        raise ValueError("Email message exceeds the configured size limit.")
    return message


class _PinnedSMTP(smtplib.SMTP):
    def __init__(self, *args: Any, pinned_ip: str, **kwargs: Any) -> None:
        self._pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        return socket.create_connection((self._pinned_ip, port), timeout=timeout)


class _PinnedSMTPSSL(smtplib.SMTP_SSL):
    def __init__(self, *args: Any, pinned_ip: str, **kwargs: Any) -> None:
        self._pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        raw = socket.create_connection((self._pinned_ip, port), timeout=timeout)
        return self.context.wrap_socket(raw, server_hostname=host)


class SmtpNotificationAdapter:
    def __init__(
        self,
        *,
        resolve_secret: Any,
        egress_policy: EgressPolicyEngine,
        timeout_seconds: float = 10.0,
    ) -> None:
        self._resolve_secret = resolve_secret
        self._egress = egress_policy
        self._timeout = min(max(timeout_seconds, 1.0), 30.0)

    async def deliver(self, request: NotificationSendRequest) -> NotificationAdapterResult:
        return await self._send(request)

    async def send_test(self, request: NotificationSendRequest) -> NotificationAdapterResult:
        return await self._send(request)

    async def _send(self, request: NotificationSendRequest) -> NotificationAdapterResult:
        try:
            secret = await self._resolve_secret(request)
            config = json.loads(secret.decode("utf-8", errors="strict"))
            if not isinstance(config, dict):
                raise ValueError("invalid smtp configuration")
            host = config.get("host")
            port = config.get("port")
            sender = config.get("sender")
            username = config.get("username")
            password = config.get("password")
            mode = config.get("tls_mode", "starttls")
            if (
                not isinstance(host, str)
                or not host
                or not isinstance(port, int)
                or isinstance(port, bool)
                or not 1 <= port <= 65535
                or mode not in {"starttls", "ssl"}
                or not isinstance(sender, str)
                or (username is not None and not isinstance(username, str))
                or (password is not None and not isinstance(password, str))
                or ((username is None) != (password is None))
            ):
                raise ValueError("invalid smtp configuration")
            if (mode == "starttls" and port != 587) or (mode == "ssl" and port != 465):
                raise ValueError("SMTP must use registered submission ports with TLS.")
            # ADR-037 stores endpoint allowlisting in the HTTPS endpoint registry. Evaluate
            # that exact registered host/port policy, then use the returned pinned address
            # with the SMTP TLS transport below (never issue an HTTP request).
            endpoint = await self._egress.evaluate_and_resolve(
                adapter="smtp", url=httpx.URL(f"https://{host}:{port}")
            )
            message = build_email_message(
                sender=sender,
                recipient=request.address,
                title=request.title,
                body=request.body,
                correlation_id=request.correlation_id,
                deep_link=request.deep_link,
            )
            status, code, ambiguous = await asyncio.to_thread(
                self._send_sync,
                host=host,
                port=port,
                pinned_ip=endpoint.pinned_ips[0].compressed,
                tls_mode=mode,
                username=username,
                password=password,
                sender=sender,
                recipient=request.address,
                message=message,
            )
            return NotificationAdapterResult(
                http_status=status,
                timed_out_after_send=ambiguous,
                error_code=code,
            )
        except asyncio.CancelledError:
            raise
        except (TimeoutError, smtplib.SMTPServerDisconnected, OSError):
            return NotificationAdapterResult(error_code="smtp_transport_error")
        except ValueError:
            return NotificationAdapterResult(http_status=400, error_code="invalid_smtp_config")
        except Exception:
            return NotificationAdapterResult(error_code="smtp_delivery_failed")

    def _send_sync(
        self,
        *,
        host: str,
        port: int,
        pinned_ip: str,
        tls_mode: str,
        username: str | None,
        password: str | None,
        sender: str,
        recipient: str,
        message: EmailMessage,
    ) -> tuple[int, str | None, bool]:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        client: smtplib.SMTP | None = None
        submission_started = False
        try:
            if tls_mode == "ssl":
                client = _PinnedSMTPSSL(
                    host,
                    port,
                    timeout=self._timeout,
                    context=context,
                    pinned_ip=pinned_ip,
                )
            else:
                client = _PinnedSMTP(host, port, timeout=self._timeout, pinned_ip=pinned_ip)
            client.ehlo()
            if tls_mode == "starttls":
                if not client.has_extn("starttls"):
                    return 503, "smtp_starttls_required", False
                client.starttls(context=context)
                client.ehlo()
            if username is not None and password is not None:
                client.login(username, password)
            submission_started = True
            refused = client.send_message(message, from_addr=sender, to_addrs=[recipient])
            if refused:
                code = next(iter(refused.values()))[0]
                if 500 <= code < 600:
                    return 400, "recipient_bounced", False
                return 503, "smtp_temporary_failure", False
            return 250, None, False
        except (TimeoutError, smtplib.SMTPServerDisconnected):
            return 503, "smtp_transport_unknown", submission_started
        except smtplib.SMTPRecipientsRefused as exc:
            statuses = [int(value[0]) for value in exc.recipients.values()]
            if statuses and all(500 <= status < 600 for status in statuses):
                return 400, "recipient_bounced", False
            return 503, "smtp_temporary_failure", False
        except smtplib.SMTPResponseException as exc:
            code = int(exc.smtp_code)
            if code >= 500:
                return 400, "smtp_permanent_rejection", False
            return 503, "smtp_temporary_failure", False
        finally:
            if client is not None:
                with contextlib.suppress(OSError):
                    client.close()
