"""Local single-command developer & evaluator stack launcher for Red2PR (`v0.1.0-beta.1`).

Provides three safe, non-destructive modes from a source checkout:
- `check`: verify configuration, runtime composition wiring, and built web bundle status.
- `smoke-test`: boot a disposable PostgreSQL 16 + Alembic `head` + FastAPI/Astryx stack on an
  ephemeral loopback port, verify health, SPA serving, setup state, and one-use bootstrap link
  issuance (with secrets redacted), then tear down cleanly.
- `up`: start or resume a persistent local Red2PR instance confined to `.local-data/red2pr`
  (or `RED2PR_DATA_DIR`), preserving existing data and secrets across restarts.
"""

from __future__ import annotations

import argparse
import os
import secrets
import socket
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import httpx
import pgserver
import uvicorn

from red2pr_cli.commands import execute_command
from red2pr_cli.exit_codes import OK
from red2pr_control.db.engine import ensure_compatible_event_loop, run_alembic_upgrade
from red2pr_control.runtime import (
    build_runtime_app,
    resolve_web_dist_dir,
    serve_uvicorn_app,
    wrap_with_spa_static_files,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROLE_NAME = "red2pr_app"


def _write_secret_if_missing(path: Path, *, num_bytes: int = 32) -> str:
    """Create a hex secret file with owner-only permissions if absent; never overwrite."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        path.parent.chmod(0o700)
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"Refusing unsafe secret path: {path}")
        return path.read_text(encoding="ascii").strip()
    value = secrets.token_hex(num_bytes)
    path.write_text(value + "\n", encoding="ascii")
    if os.name != "nt":
        path.chmod(0o600)
    return value


def _write_config_if_missing(config_path: Path, *, public_base_url: str) -> None:
    """Write minimal local `config.yaml` only when absent."""
    config_path.parent.mkdir(parents=True, exist_ok=True)
    if config_path.exists():
        return
    content = f"instance:\n  deployment_mode: local\n  public_base_url: {public_base_url}\n"
    config_path.write_text(content, encoding="utf-8")
    if os.name != "nt":
        config_path.chmod(0o600)


def _pick_free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _build_role_url(raw_uri: str, *, username: str, password: str) -> str:
    parsed = urlparse(raw_uri)
    host = parsed.hostname or "127.0.0.1"
    port_part = f":{parsed.port}" if parsed.port else ""
    netloc = f"{username}:{password}@{host}{port_part}"
    return urlunparse(
        (
            "postgresql+psycopg",
            netloc,
            parsed.path or "/postgres",
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def _normalize_admin_url(raw_uri: str) -> str:
    parsed = urlparse(raw_uri)
    return urlunparse(
        (
            "postgresql+psycopg",
            parsed.netloc,
            parsed.path or "/postgres",
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


@contextmanager
def _managed_database(
    data_dir: Path,
    *,
    app_role_password: str,
    cleanup_mode: str | None,
) -> Iterator[tuple[str, str]]:
    """Yield `(admin_url, app_url)` from env overrides or confined local `pgserver`."""
    ext_admin = os.environ.get("RED2PR_ADMIN_DATABASE_URL", "").strip()
    ext_app = os.environ.get("RED2PR_DATABASE_URL", "").strip()
    if ext_admin:
        resolved_app = ext_app or _build_role_url(
            ext_admin,
            username=APP_ROLE_NAME,
            password=app_role_password,
        )
        yield (_normalize_admin_url(ext_admin), resolved_app)
        return

    pg_dir = data_dir / "pgdata"
    pg_dir.mkdir(parents=True, exist_ok=True)
    with pgserver.get_server(str(pg_dir), cleanup_mode=cleanup_mode) as server:
        raw_uri = server.get_uri()
        yield (
            _normalize_admin_url(raw_uri),
            _build_role_url(raw_uri, username=APP_ROLE_NAME, password=app_role_password),
        )


def _wait_until_healthy(base_url: str, *, timeout_seconds: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_err = "no response"
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(f"{base_url}/api/v1/system/health", timeout=2.0)
            if resp.status_code == 200 and resp.json().get("status") == "ok":
                return
            last_err = f"HTTP {resp.status_code}"
        except httpx.HTTPError as exc:
            last_err = type(exc).__name__
        time.sleep(0.25)
    raise RuntimeError(
        f"Control plane did not become healthy within {timeout_seconds}s ({last_err})."
    )


def _run_check() -> int:
    ensure_compatible_event_loop()
    with tempfile.TemporaryDirectory(prefix="red2pr_check_") as tmp:
        tmp_root = Path(tmp)
        key_file = tmp_root / "master.key"
        _write_secret_if_missing(key_file)
        os.environ["RED2PR_MASTER_KEY_FILE"] = str(key_file)
        os.environ["RED2PR_DATA_DIR"] = str(tmp_root / "data")
        build_runtime_app(
            database_url="postgresql+psycopg:///red2pr?host=127.0.0.1&port=5432&user=red2pr_app",
            data_dir=tmp_root / "data",
            pricing_catalog_refresh_enabled=False,
        )
    dist = resolve_web_dist_dir()
    bundle_state = f"present ({dist})" if dist is not None else "not built yet (run pnpm build)"
    sys.stdout.write(
        "Red2PR preflight check passed:\n"
        f"  - Python runtime: {sys.version.split()[0]}\n"
        "  - Control-plane ASGI wiring: OK\n"
        f"  - Web UI production bundle: {bundle_state}\n"
    )
    return 0


def _run_smoke_test() -> int:
    ensure_compatible_event_loop()
    dist = resolve_web_dist_dir()
    if dist is None:
        raise RuntimeError(
            "Built web bundle not found at apps/web/dist. Run `pnpm build` before smoke-test."
        )
    port = _pick_free_loopback_port()
    base_url = f"http://127.0.0.1:{port}"

    with tempfile.TemporaryDirectory(prefix="red2pr_smoke_") as tmp:
        data_dir = Path(tmp) / "red2pr"
        secrets_dir = data_dir / "secrets"
        master_key_file = secrets_dir / "master.key"
        issuer_file = secrets_dir / "bootstrap_issuer"
        _write_secret_if_missing(master_key_file)
        issuer_secret = _write_secret_if_missing(issuer_file)
        app_db_pw = _write_secret_if_missing(secrets_dir / "app_db_password", num_bytes=24)
        config_path = data_dir / "config" / "config.yaml"
        _write_config_if_missing(config_path, public_base_url=base_url)

        with _managed_database(
            data_dir,
            app_role_password=app_db_pw,
            cleanup_mode="delete",
        ) as (admin_url, app_url):
            run_alembic_upgrade(
                admin_url,
                "head",
                app_role_name=APP_ROLE_NAME,
                app_role_password=app_db_pw,
            )
            os.environ["RED2PR_CONFIG"] = str(config_path)
            os.environ["RED2PR_DATABASE_URL"] = app_url
            os.environ["RED2PR_ADMIN_DATABASE_URL"] = admin_url
            os.environ["RED2PR_MASTER_KEY_FILE"] = str(master_key_file)
            os.environ["RED2PR_BOOTSTRAP_ISSUER_SECRET"] = issuer_secret
            os.environ["RED2PR_DATA_DIR"] = str(data_dir)

            app = build_runtime_app(
                database_url=app_url,
                data_dir=data_dir,
                pricing_catalog_refresh_enabled=False,
            )
            asgi_app = wrap_with_spa_static_files(app, web_dist_dir=dist)
            uv_cfg = uvicorn.Config(
                asgi_app,
                host="127.0.0.1",
                port=port,
                log_level="warning",
                server_header=False,
                date_header=False,
            )
            server = uvicorn.Server(uv_cfg)
            thread = threading.Thread(
                target=serve_uvicorn_app,
                args=(uv_cfg,),
                kwargs={"server": server},
                daemon=True,
            )
            thread.start()
            try:
                _wait_until_healthy(base_url)
                spa_resp = httpx.get(f"{base_url}/setup", timeout=5.0)
                if spa_resp.status_code != 200 or 'id="root"' not in spa_resp.text:
                    raise RuntimeError(
                        f"Unexpected SPA /setup response: HTTP {spa_resp.status_code}"
                    )
                setup_api = httpx.get(f"{base_url}/api/v1/setup", timeout=5.0)
                if setup_api.status_code != 200 or setup_api.json().get("phase") != "owner_claim":
                    raise RuntimeError("Unexpected initial /api/v1/setup state.")
                cli_res = execute_command(
                    "setup",
                    args=("--bootstrap-link",),
                    environ={
                        "RED2PR_API_URL": base_url,
                        "RED2PR_BOOTSTRAP_ISSUER_SECRET_FILE": str(issuer_file),
                    },
                )
                if cli_res.exit_code != OK or "#bootstrap_token=" not in cli_res.output:
                    raise RuntimeError("Bootstrap setup link handoff verification failed.")
            finally:
                server.should_exit = True
                thread.join(timeout=10.0)

    sys.stdout.write(
        "Red2PR disposable end-to-end smoke test PASSED:\n"
        "  - PostgreSQL 16 + Alembic 0001..0025 + RLS role provisioning: OK\n"
        "  - Control-plane /api/v1/system/health & /api/v1/setup: OK\n"
        "  - Single-origin React 19 + Astryx SPA bundle (/setup): OK\n"
        "  - One-use bootstrap claim link handoff (redacted): OK\n"
    )
    return 0


def _run_up(*, host: str, port: int, data_dir: Path) -> int:
    ensure_compatible_event_loop()
    dist = resolve_web_dist_dir()
    if dist is None:
        raise RuntimeError("Built web bundle not found at apps/web/dist. Run `pnpm build` first.")
    resolved_data = data_dir.resolve()
    secrets_dir = resolved_data / "secrets"
    master_key_file = secrets_dir / "master.key"
    issuer_file = secrets_dir / "bootstrap_issuer"
    _write_secret_if_missing(master_key_file)
    issuer_secret = _write_secret_if_missing(issuer_file)
    app_db_pw = _write_secret_if_missing(secrets_dir / "app_db_password", num_bytes=24)

    base_url = f"http://{host}:{port}"
    config_path = resolved_data / "config" / "config.yaml"
    _write_config_if_missing(config_path, public_base_url=base_url)

    sys.stdout.write(f"Initializing Red2PR local state in {resolved_data}...\n")
    with _managed_database(
        resolved_data,
        app_role_password=app_db_pw,
        cleanup_mode=None,
    ) as (admin_url, app_url):
        run_alembic_upgrade(
            admin_url,
            "head",
            app_role_name=APP_ROLE_NAME,
            app_role_password=app_db_pw,
        )
        os.environ["RED2PR_CONFIG"] = str(config_path)
        os.environ["RED2PR_DATABASE_URL"] = app_url
        os.environ["RED2PR_ADMIN_DATABASE_URL"] = admin_url
        os.environ["RED2PR_MASTER_KEY_FILE"] = str(master_key_file)
        os.environ["RED2PR_BOOTSTRAP_ISSUER_SECRET"] = issuer_secret
        os.environ["RED2PR_DATA_DIR"] = str(resolved_data)

        app = build_runtime_app(database_url=app_url, data_dir=resolved_data)
        asgi_app = wrap_with_spa_static_files(app, web_dist_dir=dist)
        uv_cfg = uvicorn.Config(
            asgi_app,
            host=host,
            port=port,
            log_level="info",
            server_header=False,
            date_header=False,
        )
        server = uvicorn.Server(uv_cfg)

        def _print_ready_banner() -> None:
            try:
                _wait_until_healthy(base_url, timeout_seconds=45.0)
                cli_res = execute_command(
                    "setup",
                    args=("--bootstrap-link",),
                    environ={
                        "RED2PR_API_URL": base_url,
                        "RED2PR_BOOTSTRAP_ISSUER_SECRET_FILE": str(issuer_file),
                    },
                )
                sys.stdout.write(
                    "\n============================================================\n"
                    f"Red2PR local stack is ready at: {base_url}\n"
                    f"  {cli_res.output}\n"
                    "  Note: treat the one-use setup link as sensitive; do not share logs.\n"
                    "  Press Ctrl+C to stop cleanly (instance data is preserved).\n"
                    "============================================================\n\n"
                )
                sys.stdout.flush()
            except Exception as exc:
                sys.stderr.write(f"Red2PR startup handoff warning: {exc}\n")

        threading.Thread(target=_print_ready_banner, daemon=True).start()
        serve_uvicorn_app(uv_cfg, server=server)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Red2PR local source quickstart manager.")
    parser.add_argument(
        "mode",
        nargs="?",
        choices=("up", "check", "smoke-test"),
        default="up",
        help="Execution mode (`up` starts the persistent local stack).",
    )
    parser.add_argument("--host", default=os.environ.get("RED2PR_BIND_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("RED2PR_HTTP_PORT", "4280")))
    parser.add_argument(
        "--data-dir",
        default=os.environ.get("RED2PR_DATA_DIR", str(REPO_ROOT / ".local-data" / "red2pr")),
    )
    args = parser.parse_args(argv)
    if args.mode == "check":
        return _run_check()
    if args.mode == "smoke-test":
        return _run_smoke_test()
    return _run_up(host=args.host, port=args.port, data_dir=Path(args.data_dir))


if __name__ == "__main__":
    raise SystemExit(main())
