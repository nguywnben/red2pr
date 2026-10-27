"""Deterministic secret redaction engine v1 (SEC-017, NFR-13).

Scrubs provider tokens, bearer headers, PEM private keys, URL credentials,
inline secret assignments, sensitive mapping keys, and registered runtime
secret canaries (including URL-encoded and Base64-encoded canary variants)
before any data enters logs, OpenTelemetry spans, error DTOs, or outbound payloads.
"""

from __future__ import annotations

import base64
import re
import threading
import urllib.parse
from collections.abc import Mapping, Sequence
from typing import Any

REDACTION_VERSION: str = "v1"
MIN_CANARY_LENGTH: int = 6
MAX_REDACTION_DEPTH: int = 16

_SENSITIVE_KEY_NAMES: frozenset[str] = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "auth_token",
        "authorization",
        "bootstrap_token",
        "bot_token",
        "client_secret",
        "cookie",
        "master_key",
        "otp",
        "passphrase",
        "password",
        "private_key",
        "proxy-authorization",
        "recovery_code",
        "refresh_token",
        "secret",
        "secret_header",
        "secret_key",
        "secret_token",
        "session_token",
        "set-cookie",
        "smtp_password",
        "token",
        "webhook_secret",
        "x-api-key",
        "x-gitlab-token",
        "x-hub-signature-256",
        "x-telegram-bot-api-secret-token",
    }
)

_TOKEN_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
        "[REDACTED:PEM_PRIVATE_KEY]",
    ),
    (
        re.compile(r"(?i)\b(authorization\s*[:=]\s*(?:bearer|basic|token)\s+)([^\s,;\"']+)"),
        r"\1[REDACTED:AUTH_HEADER]",
    ),
    (
        re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9._~+/=-]{12,})"),
        r"\1[REDACTED:BEARER_TOKEN]",
    ),
    (
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,255}\b"),
        "[REDACTED:GITHUB_TOKEN]",
    ),
    (
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b"),
        "[REDACTED:GITHUB_PAT]",
    ),
    (
        re.compile(r"\b(?:glpat|glptt|gldt|glrt|glsoat)-[A-Za-z0-9_-]{16,255}\b"),
        "[REDACTED:GITLAB_TOKEN]",
    ),
    (
        re.compile(r"\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{16,255}\b"),
        "[REDACTED:SLACK_TOKEN]",
    ),
    (
        re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+"),
        "https://hooks.slack.com/services/[REDACTED:SLACK_WEBHOOK]",
    ),
    (
        re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[A-Za-z0-9/_-]+"),
        "https://discord.com/api/webhooks/[REDACTED:DISCORD_WEBHOOK]",
    ),
    (
        re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
        "[REDACTED:TELEGRAM_BOT_TOKEN]",
    ),
    (
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "[REDACTED:AWS_ACCESS_KEY]",
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "[REDACTED:JWT]",
    ),
    (
        re.compile(r"(https?://)([^/\s:@]+):([^/\s@]+)@"),
        r"\1[REDACTED:URL_CREDENTIALS]@",
    ),
    (
        re.compile(
            r"(?i)\b((?:password|passwd|secret|api_key|apikey|token|webhook_secret|private_key|key)"
            r"\s*[=:]\s*)([^\s,;\"'&]{6,})"
        ),
        r"\1[REDACTED:SECRET_VALUE]",
    ),
)


def _is_sensitive_key(key: str) -> bool:
    normalized = key.strip().lower().replace("_", "-")
    if normalized in _SENSITIVE_KEY_NAMES or key.strip().lower() in _SENSITIVE_KEY_NAMES:
        return True
    return any(
        normalized.endswith(suffix)
        for suffix in ("-secret", "-token", "-password", "-api-key", "-private-key")
    )


class Redactor:
    """Thread-safe deterministic secret scrubber supporting registered canary values."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._canary_literals: set[str] = set()
        self._canary_regex: re.Pattern[str] | None = None

    def register_canary(self, secret_value: str) -> None:
        """Register an exact runtime secret value and its URL/Base64-encoded forms."""
        if not secret_value or len(secret_value) < MIN_CANARY_LENGTH:
            return
        variants = {secret_value}

        b64_std = base64.b64encode(secret_value.encode("utf-8")).decode("ascii")
        b64_url = base64.urlsafe_b64encode(secret_value.encode("utf-8")).decode("ascii")
        variants.add(b64_std)
        variants.add(b64_std.rstrip("="))
        variants.add(b64_url)
        variants.add(b64_url.rstrip("="))

        url_enc = urllib.parse.quote(secret_value, safe="")
        url_plus = urllib.parse.quote_plus(secret_value)
        if len(url_enc) >= MIN_CANARY_LENGTH:
            variants.add(url_enc)
        if len(url_plus) >= MIN_CANARY_LENGTH:
            variants.add(url_plus)

        with self._lock:
            before = len(self._canary_literals)
            self._canary_literals.update(v for v in variants if len(v) >= MIN_CANARY_LENGTH)
            if len(self._canary_literals) != before:
                ordered = sorted(self._canary_literals, key=len, reverse=True)
                joined = "|".join(re.escape(item) for item in ordered)
                self._canary_regex = re.compile(joined)

    def redact_text(self, text: str) -> str:
        """Scrub registered secret canaries and known credential patterns from a string."""
        if not text:
            return text
        result = text
        with self._lock:
            canary_re = self._canary_regex
        if canary_re is not None:
            result = canary_re.sub("[REDACTED:CANARY]", result)
        for pattern, replacement in _TOKEN_PATTERNS:
            result = pattern.sub(replacement, result)
        return result

    def redact_value(self, value: Any, *, _depth: int = 0) -> Any:
        """Recursively scrub strings and sensitive keys without mutating caller containers."""
        if _depth > MAX_REDACTION_DEPTH:
            return "[REDACTED:MAX_DEPTH]"
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, bytes):
            decoded = value.decode("utf-8", errors="replace")
            return self.redact_text(decoded)
        if isinstance(value, Mapping):
            scrubbed_dict: dict[str, Any] = {}
            for raw_k, raw_v in value.items():
                key_str = str(raw_k)
                if _is_sensitive_key(key_str):
                    scrubbed_dict[key_str] = "[REDACTED:SENSITIVE_KEY]"
                else:
                    scrubbed_dict[key_str] = self.redact_value(raw_v, _depth=_depth + 1)
            return scrubbed_dict
        if isinstance(value, tuple):
            return tuple(self.redact_value(item, _depth=_depth + 1) for item in value)
        if isinstance(value, Sequence):
            return [self.redact_value(item, _depth=_depth + 1) for item in value]
        return self.redact_text(str(value))


DEFAULT_REDACTOR = Redactor()
