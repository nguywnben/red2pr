"""CLI request/exit mapping kept independent of HTTP or terminal runtimes."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlsplit

from red2pr_cli.exit_codes import (
    AUTH_OR_STEP_UP,
    BACKUP_OR_RESTORE_INTEGRITY,
    EXTERNAL_DEPENDENCY_BLOCKED,
    MIGRATION_OR_COMPATIBILITY,
    OK,
    PREREQUISITE_OR_SIGNATURE,
    RUNTIME_DEGRADED,
    USAGE_OR_CONFIG,
)

COMMANDS = (
    "install",
    "setup",
    "status",
    "doctor",
    "logs",
    "worker",
    "update",
    "backup",
    "restore",
    "rotate-secrets",
    "uninstall",
)


@dataclass(frozen=True)
class CliResult:
    exit_code: int
    output: str


HttpCall = Callable[[str, str, bytes | None, dict[str, str]], tuple[int, bytes]]


class UnsafePurgePath(ValueError):
    """Reject purge targets that can escape configured Red2PR-owned roots."""


def _validate_purge_path(target: Path, roots: tuple[Path, ...]) -> Path:
    raw = Path(os.path.abspath(target))
    cursor = Path(raw.anchor)
    for part in raw.parts[1:]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise UnsafePurgePath("Purge target contains a symlink component.")
    resolved = raw.resolve(strict=False)
    home = Path.home().resolve(strict=False)
    for root in roots:
        owned_root = root.resolve(strict=True)
        if resolved != owned_root and resolved.is_relative_to(owned_root):
            if resolved == Path(resolved.anchor) or resolved == home or resolved in home.parents:
                break
            return resolved
    raise UnsafePurgePath("Purge target is outside configured Red2PR data directories.")


def _uninstall(args: Sequence[str], env: dict[str, str]) -> CliResult:
    if "--purge" not in args:
        return _uninstall_services(args)
    try:
        target = Path(args[args.index("--path") + 1])
        roots = tuple(
            Path(env[key])
            for key in ("RED2PR_DATA_DIRECTORY", "RED2PR_BACKUP_DIRECTORY")
            if env.get(key)
        )
        if not roots:
            raise UnsafePurgePath("Owned data roots are not configured.")
        resolved = _validate_purge_path(target, roots)
    except (IndexError, OSError, ValueError):
        return CliResult(
            USAGE_OR_CONFIG,
            "Purge requires --path within a configured Red2PR data or backup directory.",
        )
    if "--dry-run" in args:
        service_plan = _uninstall_services(("--dry-run",))
        if service_plan.exit_code != OK:
            return service_plan
        return CliResult(
            OK,
            f"{service_plan.output} Purge target is confined and would be removed: {resolved}",
        )
    if "--confirm-purge" not in args:
        return CliResult(USAGE_OR_CONFIG, "Add --confirm-purge to remove the confined target.")
    if "--confirm-uninstall" not in args:
        return CliResult(
            USAGE_OR_CONFIG,
            "Add --confirm-uninstall as well as --confirm-purge to remove services and data.",
        )
    service_result = _uninstall_services(("--confirm-uninstall",))
    if service_result.exit_code != OK:
        return service_result
    try:
        if resolved.exists():
            shutil.rmtree(resolved)
    except OSError:
        return CliResult(
            RUNTIME_DEGRADED,
            "Services were removed but the confined data purge failed; inspect the target "
            "before retrying.",
        )
    return CliResult(OK, "Confined Red2PR data directory was removed.")


def _uninstall_services(args: Sequence[str]) -> CliResult:
    """Remove only the planned Red2PR systemd units; retain all instance data."""
    systemctl = shutil.which("systemctl")
    if os.name != "posix" or not systemctl:
        return CliResult(
            RUNTIME_DEGRADED,
            "Service uninstall is supported on systemd hosts only. "
            "Instance data, backups, and encryption keys were preserved.",
        )
    return _uninstall_systemd_units(
        args,
        systemctl_path=systemctl,
        unit_roots=(Path("/etc/systemd/system"), Path("/usr/local/lib/systemd/system")),
    )


def _uninstall_systemd_units(
    args: Sequence[str],
    *,
    systemctl_path: str,
    unit_roots: tuple[Path, ...],
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> CliResult:
    """Systemd implementation separated for hermetic operation tests."""
    units = ("red2pr-control.service", "red2pr-worker.service")
    installed: list[tuple[str, Path]] = []
    try:
        for unit in units:
            result = run(
                [systemctl_path, "show", "--property=FragmentPath", "--value", unit],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode != 0:
                return CliResult(
                    RUNTIME_DEGRADED,
                    "Could not inspect installed services; no files were removed. "
                    "Instance data, backups, and encryption keys were preserved.",
                )
            fragment = result.stdout.strip()
            if not fragment:
                continue
            path = Path(fragment)
            resolved = path.resolve(strict=True)
            if (
                path.name != unit
                or resolved.name != unit
                or not any(
                    resolved.is_relative_to(root.resolve(strict=False)) for root in unit_roots
                )
            ):
                return CliResult(
                    RUNTIME_DEGRADED,
                    f"Service definition for {unit} is outside managed systemd directories; "
                    "nothing was removed.",
                )
            if path.is_symlink() or not resolved.is_file():
                return CliResult(
                    RUNTIME_DEGRADED,
                    f"Service definition for {unit} is not a regular managed file; "
                    "nothing was removed.",
                )
            installed.append((unit, resolved))
    except (OSError, subprocess.SubprocessError, RuntimeError):
        return CliResult(
            RUNTIME_DEGRADED,
            "Could not inspect installed services; no files were removed. "
            "Instance data, backups, and encryption keys were preserved.",
        )

    if not installed:
        return CliResult(
            OK,
            "No Red2PR services are installed. Instance data, backups, and encryption keys "
            "were preserved.",
        )
    if "--dry-run" in args:
        names = ", ".join(unit for unit, _ in installed)
        return CliResult(
            OK,
            f"Would stop and remove {names}. Instance data, backups, and encryption keys "
            "would be preserved.",
        )
    if "--confirm-uninstall" not in args:
        return CliResult(
            USAGE_OR_CONFIG,
            "Add --confirm-uninstall to stop and remove the listed Red2PR services; "
            "instance data, backups, and encryption keys are preserved.",
        )

    try:
        for unit, _ in installed:
            for action in ("stop", "disable"):
                result = run(
                    [systemctl_path, action, unit],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode != 0:
                    return CliResult(
                        RUNTIME_DEGRADED,
                        f"Could not {action} {unit}; service definitions and instance data "
                        "were preserved.",
                    )
        for _, path in installed:
            path.unlink()
        result = run(
            [systemctl_path, "daemon-reload"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return CliResult(
                RUNTIME_DEGRADED,
                "Service definitions were removed but systemd reload failed. "
                "Instance data, backups, and encryption keys were preserved.",
            )
    except (OSError, subprocess.SubprocessError):
        return CliResult(
            RUNTIME_DEGRADED,
            "Service removal was interrupted; instance data, backups, and encryption keys "
            "were preserved. Inspect systemd state before retrying.",
        )
    return CliResult(
        OK,
        "Red2PR services were stopped and removed. Instance data, backups, and encryption "
        "keys were preserved.",
    )


def _http_call(
    url: str, method: str, body: bytes | None, headers: dict[str, str]
) -> tuple[int, bytes]:
    if not _safe_api_url(url):
        return 0, b""
    request = urllib.request.Request(url, data=body, headers=headers, method=method)  # noqa: S310
    try:
        # Redirects are deliberately disabled to prevent credentials being forwarded to
        # another origin; _safe_api_url restricts the initial URL to HTTPS/loopback HTTP.
        opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(request, timeout=15) as response:
            return response.status, response.read(8 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(64 * 1024)
    except (urllib.error.URLError, TimeoutError, OSError):
        return 0, b""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> urllib.request.Request | None:
        return None


def _safe_api_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        return bool(
            parsed.scheme == "https"
            and parsed.hostname
            and parsed.username is None
            and parsed.password is None
            and not parsed.fragment
        ) or bool(
            parsed.scheme == "http"
            and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
            and parsed.username is None
            and parsed.password is None
            and not parsed.fragment
        )
    except ValueError:
        return False


def _status_to_exit(status: int, payload: bytes) -> int:
    if status in (200, 201, 202, 204):
        return OK
    if status in (401, 403):
        return AUTH_OR_STEP_UP
    if status in (409, 412):
        try:
            code = str(json.loads(payload).get("code", ""))
        except (ValueError, AttributeError):
            code = ""
        if any(
            term in code for term in ("backup", "restore", "signature", "integrity", "artifact")
        ):
            return BACKUP_OR_RESTORE_INTEGRITY
        return MIGRATION_OR_COMPATIBILITY
    if status == 422:
        return USAGE_OR_CONFIG
    if status == 503:
        return EXTERNAL_DEPENDENCY_BLOCKED
    if status == 0 or status >= 500:
        return RUNTIME_DEGRADED
    return PREREQUISITE_OR_SIGNATURE


def _redact_response(value: object, *, depth: int = 0) -> object:
    if depth > 12:
        return "[REDACTED:DEPTH_LIMIT]"
    if isinstance(value, dict):
        sensitive = {
            "token",
            "secret",
            "password",
            "authorization",
            "cookie",
            "private_key",
            "client_secret",
            "api_key",
        }
        return {
            key: "[REDACTED]"
            if key.lower() in sensitive
            or any(part in key.lower() for part in ("secret", "token", "password", "credential"))
            else _redact_response(item, depth=depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_response(item, depth=depth + 1) for item in value[:10_000]]
    if isinstance(value, str):
        return re.sub(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{12,}", r"\1[REDACTED]", value)[:16_384]
    return value


def _read_local_logs(env: dict[str, str], *, tail: int = 200) -> CliResult:
    raw_path = env.get("RED2PR_LOG_FILE", "").strip()
    raw_root = env.get("RED2PR_LOG_DIRECTORY", "").strip()
    if not raw_path or not raw_root:
        return CliResult(
            USAGE_OR_CONFIG,
            "Set RED2PR_LOG_FILE and RED2PR_LOG_DIRECTORY to the owned Red2PR log file "
            "and directory.",
        )
    try:
        root = Path(raw_root).resolve(strict=True)
    except OSError:
        return CliResult(
            PREREQUISITE_OR_SIGNATURE, "Configured local log directory is unavailable."
        )
    path = Path(raw_path)
    absolute = Path(os.path.abspath(path))
    if not absolute.is_relative_to(root) or absolute == root:
        return CliResult(
            PREREQUISITE_OR_SIGNATURE, "Configured local log file is missing or unsafe."
        )
    cursor = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        cursor = cursor / part
        if cursor.is_symlink():
            return CliResult(
                PREREQUISITE_OR_SIGNATURE, "Configured local log file is missing or unsafe."
            )
    if not absolute.is_file():
        return CliResult(
            PREREQUISITE_OR_SIGNATURE, "Configured local log file is missing or unsafe."
        )
    try:
        lines: deque[str] = deque(maxlen=tail)
        with absolute.open("r", encoding="utf-8", errors="replace") as stream:
            lines.extend(stream)
    except OSError:
        return CliResult(PREREQUISITE_OR_SIGNATURE, "Configured local log file could not be read.")
    redacted = []
    for line in lines:
        line = re.sub(
            r"(?i)(authorization|cookie|password|secret|token|api[_-]?key)(\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+",
            r"\1\2[REDACTED]",
            line,
        )
        line = re.sub(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{12,}", r"\1[REDACTED]", line)
        redacted.append(line.rstrip("\r\n")[:16_384])
    return CliResult(OK, "\n".join(redacted))


def execute_command(
    command: str,
    *,
    args: Sequence[str] = (),
    environ: dict[str, str] | None = None,
    http_call: HttpCall = _http_call,
) -> CliResult:
    env = environ if environ is not None else dict(os.environ)
    if command not in COMMANDS:
        return CliResult(USAGE_OR_CONFIG, "Unknown command.")
    base = env.get("RED2PR_API_URL", "").rstrip("/")
    if base and not _safe_api_url(base):
        return CliResult(
            USAGE_OR_CONFIG,
            "RED2PR_API_URL must use HTTPS or loopback HTTP without credentials.",
        )
    if command == "uninstall":
        return _uninstall(args, env)
    if command == "logs":
        return _read_local_logs(env)
    if command == "install":
        if not base:
            return CliResult(
                USAGE_OR_CONFIG, "Set RED2PR_API_URL to the installed control plane URL."
            )
        endpoint, method, body = "/api/v1/setup", "GET", None
    elif command == "setup":
        endpoint, method, body = "/api/v1/setup", "GET", None
    elif command == "status":
        endpoint, method, body = "/api/v1/system/status", "GET", None
    elif command == "doctor":
        endpoint, method, body = "/api/v1/system/doctor", "GET", None
    elif command == "worker":
        endpoint, method, body = "/api/v1/system/workers", "GET", None
    elif command == "update":
        try:
            version = env["RED2PR_TARGET_VERSION"]
            revision = env["RED2PR_TARGET_SCHEMA_REVISION"]
            protocols = json.loads(env["RED2PR_TARGET_WORKER_PROTOCOLS"])
            body = json.dumps(
                {
                    "target_version": version,
                    "target_schema_revision": revision,
                    "target_worker_protocols": protocols,
                }
            ).encode()
        except (KeyError, ValueError):
            return CliResult(
                USAGE_OR_CONFIG,
                "Set target version, schema revision, and worker protocols for preflight.",
            )
        endpoint, method = "/api/v1/system/upgrade-preflight", "POST"
    elif command == "backup":
        endpoint, method, body = "/api/v1/system/backups", "POST", b"{}"
    elif command == "restore":
        try:
            backup_id = args[args.index("--backup-id") + 1]
        except (ValueError, IndexError):
            return CliResult(
                USAGE_OR_CONFIG,
                "Usage: red2pr restore --backup-id <id> [--dry-run | "
                "--confirm-manifest-digest <sha256> --confirm-plan-digest <sha256>]",
            )
        if "--dry-run" in args and any(
            flag in args for flag in ("--confirm-manifest-digest", "--confirm-plan-digest")
        ):
            return CliResult(
                USAGE_OR_CONFIG, "Dry-run and restore confirmation are mutually exclusive."
            )
        confirmed_manifest = None
        confirmed_plan = None
        if "--confirm-manifest-digest" in args or "--confirm-plan-digest" in args:
            try:
                confirmed_manifest = args[args.index("--confirm-manifest-digest") + 1]
                confirmed_plan = args[args.index("--confirm-plan-digest") + 1]
            except (ValueError, IndexError):
                return CliResult(
                    USAGE_OR_CONFIG,
                    "Both --confirm-manifest-digest and --confirm-plan-digest are required.",
                )
            if not re.fullmatch(r"[0-9a-f]{64}", confirmed_manifest) or not re.fullmatch(
                r"[0-9a-f]{64}", confirmed_plan
            ):
                return CliResult(
                    USAGE_OR_CONFIG, "Restore confirmation digests must be SHA-256 hex."
                )
        endpoint, method, body = (
            "/api/v1/system/restore/dry-run",
            "POST",
            json.dumps({"backup_id": backup_id}).encode(),
        )
    elif command == "rotate-secrets":
        workspace_id = env.get("RED2PR_WORKSPACE_ID", "").strip()
        if not workspace_id:
            return CliResult(
                USAGE_OR_CONFIG, "Set RED2PR_WORKSPACE_ID for the owner key-rotation operation."
            )
        endpoint, method, body = (
            f"/api/v1/workspaces/{quote(workspace_id, safe='')}/security/secrets/rotate",
            "POST",
            b"{}",
        )
    else:
        return CliResult(USAGE_OR_CONFIG, "Command configuration is invalid.")
    if not base:
        return CliResult(USAGE_OR_CONFIG, "Set RED2PR_API_URL to the control plane URL.")
    headers = {"Accept": "application/json"}
    session_cookie = env.get("RED2PR_SESSION_COOKIE", "")
    csrf_token = env.get("RED2PR_CSRF_TOKEN", "")
    if session_cookie:
        headers["Cookie"] = session_cookie
    if body is not None:
        headers["Content-Type"] = "application/json"
    if method != "GET":
        if not csrf_token:
            return CliResult(
                AUTH_OR_STEP_UP, "A browser owner session CSRF token is required for this mutation."
            )
        headers["X-CSRF-Token"] = csrf_token
    if command == "restore" and confirmed_manifest is not None and confirmed_plan is not None:
        if not csrf_token:
            return CliResult(
                AUTH_OR_STEP_UP,
                "A fresh owner session, step-up, and CSRF token are required to execute restore.",
            )
        status, response = http_call(base + endpoint, method, body, headers)
        dry_run_exit = _status_to_exit(status, response)
        if dry_run_exit != OK:
            return CliResult(dry_run_exit, _safe_json_output(response))
        try:
            plan = json.loads(response.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return CliResult(RUNTIME_DEGRADED, "Control plane returned an invalid restore plan.")
        if (
            plan.get("manifest_digest") != confirmed_manifest
            or plan.get("plan_digest") != confirmed_plan
            or plan.get("compatible") is not True
        ):
            return CliResult(
                BACKUP_OR_RESTORE_INTEGRITY,
                "Restore confirmation does not match the current compatible dry-run plan.",
            )
        endpoint = "/api/v1/system/restore"
        body = json.dumps(
            {
                "backup_id": backup_id,
                "manifest_digest": confirmed_manifest,
                "plan_digest": confirmed_plan,
            }
        ).encode()
    status, response = http_call(base + endpoint, method, body, headers)
    exit_code = _status_to_exit(status, response)
    return CliResult(exit_code, _safe_json_output(response, exit_code=exit_code))


def _safe_json_output(response: bytes, *, exit_code: int = OK) -> str:
    try:
        parsed = json.loads(response.decode("utf-8")) if response else {}
        return json.dumps(_redact_response(parsed), ensure_ascii=False, indent=2)
    except (ValueError, UnicodeDecodeError):
        return "Control plane returned an invalid response."
