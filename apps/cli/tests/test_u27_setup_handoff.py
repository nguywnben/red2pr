from __future__ import annotations

import json
from pathlib import Path

from red2pr_cli.commands import COMMANDS, execute_command
from red2pr_cli.exit_codes import OK, USAGE_OR_CONFIG


def test_setup_bootstrap_link_uses_csrf_issuer_and_prints_fragment_only(tmp_path: Path) -> None:
    token = "r2pr" + "_boot_" + "fixture_0123456789"
    issuer_secret = "a" * 64
    issuer_secret_file = tmp_path / "bootstrap_issuer"
    issuer_secret_file.write_text(issuer_secret, encoding="ascii")
    issuer_secret_file.chmod(0o600)
    calls: list[tuple[str, str, bytes | None, dict[str, str]]] = []

    def http_call(url: str, method: str, body: bytes | None, headers: dict[str, str]):
        calls.append((url, method, body, headers))
        if url.endswith("/api/v1/auth/csrf"):
            return 200, json.dumps(
                {"csrf_token": "csrf-token-for-test", "bootstrap_claim_required": False}
            ).encode()
        return 200, json.dumps(
            {"bootstrap_token": token, "expires_at": "2026-10-31T12:15:00Z"}
        ).encode()

    result = execute_command(
        "setup",
        args=("--bootstrap-link",),
        environ={
            "RED2PR_API_URL": "http://127.0.0.1:18080",
            "RED2PR_BOOTSTRAP_ISSUER_SECRET_FILE": str(issuer_secret_file),
        },
        http_call=http_call,
    )

    assert result.exit_code == OK
    assert f"#bootstrap_token={token}" in result.output
    assert result.output.count(token) == 1
    assert len(calls) == 2
    assert calls[0][1] == "GET"
    url, method, body, headers = calls[1]
    assert url.endswith("/api/v1/setup/bootstrap-token")
    assert method == "POST" and body == b"{}"
    assert headers["Cookie"] == "red2pr_csrf=csrf-token-for-test"
    assert headers["X-CSRF-Token"] == "csrf-token-for-test"
    assert headers["Origin"] == "http://127.0.0.1:18080"
    assert headers["X-Red2PR-Bootstrap-Issuer"] == issuer_secret
    assert len(COMMANDS) == 11


def test_setup_bootstrap_link_fails_closed_for_remote_url_or_missing_issuer_secret() -> None:
    remote = execute_command(
        "setup",
        args=("--bootstrap-link",),
        environ={"RED2PR_API_URL": "https://red2pr.example"},
        http_call=lambda *_: (_ for _ in ()).throw(AssertionError("network must not be called")),
    )
    no_secret = execute_command(
        "setup",
        args=("--bootstrap-link",),
        environ={"RED2PR_API_URL": "http://localhost:8080"},
        http_call=lambda *_: (_ for _ in ()).throw(AssertionError("network must not be called")),
    )

    assert remote.exit_code == USAGE_OR_CONFIG
    assert no_secret.exit_code == USAGE_OR_CONFIG


def test_setup_bootstrap_link_handles_already_claimed_without_returning_secret() -> None:
    calls = 0

    def http_call(_url: str, _method: str, _body: bytes | None, _headers: dict[str, str]):
        nonlocal calls
        calls += 1
        if calls == 1:
            return 200, b'{"csrf_token":"csrf-token-for-test","bootstrap_claim_required":false}'
        return 409, b'{"code":"already_claimed","detail":"Owner already exists."}'

    result = execute_command(
        "setup",
        args=("--bootstrap-link",),
        environ={
            "RED2PR_API_URL": "http://localhost:8080",
            "RED2PR_BOOTSTRAP_ISSUER_SECRET": "b" * 64,
        },
        http_call=http_call,
    )

    assert result.exit_code == OK
    assert "already claimed" in result.output
    assert "bootstrap_token" not in result.output
