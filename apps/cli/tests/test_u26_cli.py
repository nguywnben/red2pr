from __future__ import annotations

import subprocess

from red2pr_cli.commands import COMMANDS, CliResult, _uninstall_systemd_units, execute_command
from red2pr_cli.exit_codes import (
    AUTH_OR_STEP_UP,
    EXTERNAL_DEPENDENCY_BLOCKED,
    OK,
    RUNTIME_DEGRADED,
    USAGE_OR_CONFIG,
)


def test_cli_contract_lists_exactly_eleven_commands() -> None:
    assert COMMANDS == (
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


def test_cli_maps_auth_and_external_dependency_failures_without_leaking_payload() -> None:
    auth = execute_command(
        "status",
        environ={"RED2PR_API_URL": "https://control.example"},
        http_call=lambda *_: (403, b'{"detail":"denied","token":"secret-fixture"}'),
    )
    assert auth.exit_code == AUTH_OR_STEP_UP
    assert "secret-fixture" not in auth.output

    unavailable = execute_command(
        "backup",
        environ={"RED2PR_API_URL": "https://control.example", "RED2PR_CSRF_TOKEN": "csrf"},
        http_call=lambda *_: (503, b'{"code":"backup_signer_unavailable"}'),
    )
    assert unavailable.exit_code == EXTERNAL_DEPENDENCY_BLOCKED


def test_cli_uninstall_is_data_preserving_and_requires_explicit_purge_path_guard(
    monkeypatch,
) -> None:
    monkeypatch.setattr("red2pr_cli.commands.shutil.which", lambda _: None)
    preserved = execute_command("uninstall")
    assert preserved.exit_code == RUNTIME_DEGRADED
    assert "data" in preserved.output
    assert "preserved" in preserved.output.lower()
    denied = execute_command("uninstall", args=("--purge", "C:\\"))
    assert denied.exit_code == USAGE_OR_CONFIG


def test_systemd_uninstall_dry_run_and_confirmation_preserve_instance_data(tmp_path) -> None:
    unit_root = tmp_path / "etc" / "systemd" / "system"
    unit_root.mkdir(parents=True)
    data_file = tmp_path / "instance" / "secrets.db"
    data_file.parent.mkdir()
    data_file.write_text("preserve", encoding="utf-8")
    units = {
        "red2pr-control.service": unit_root / "red2pr-control.service",
        "red2pr-worker.service": unit_root / "red2pr-worker.service",
    }
    for path in units.values():
        path.write_text("[Service]\n", encoding="utf-8")

    calls = []

    def run(command, **_kwargs):
        calls.append(command)
        if command[1] == "show":
            return subprocess.CompletedProcess(command, 0, str(units[command[-1]]), "")
        return subprocess.CompletedProcess(command, 0, "", "")

    preview = _uninstall_systemd_units(
        ("--dry-run",),
        systemctl_path="systemctl-test-double",
        unit_roots=(unit_root,),
        run=run,
    )
    assert preview.exit_code == OK
    assert "Would stop and remove" in preview.output
    assert all(command[1] == "show" for command in calls)
    assert all(path.is_file() for path in units.values())

    uninstalled = _uninstall_systemd_units(
        ("--confirm-uninstall",),
        systemctl_path="systemctl-test-double",
        unit_roots=(unit_root,),
        run=run,
    )
    assert uninstalled.exit_code == OK
    assert not any(path.exists() for path in units.values())
    assert data_file.read_text(encoding="utf-8") == "preserve"
    assert [call[1] for call in calls if len(call) > 1][-5:] == [
        "stop",
        "disable",
        "stop",
        "disable",
        "daemon-reload",
    ]


def test_systemd_uninstall_rejects_external_service_fragment_before_mutation(tmp_path) -> None:
    managed_root = tmp_path / "etc" / "systemd" / "system"
    managed_root.mkdir(parents=True)
    external_root = tmp_path / "opt" / "red2pr"
    external_root.mkdir(parents=True)
    external_unit = external_root / "red2pr-control.service"
    external_unit.write_text("[Service]\n", encoding="utf-8")
    worker_unit = managed_root / "red2pr-worker.service"
    worker_unit.write_text("[Service]\n", encoding="utf-8")
    calls = []

    def run(command, **_kwargs):
        calls.append(command)
        path = external_unit if command[-1] == "red2pr-control.service" else worker_unit
        return subprocess.CompletedProcess(command, 0, str(path), "")

    result = _uninstall_systemd_units(
        ("--confirm-uninstall",),
        systemctl_path="systemctl-test-double",
        unit_roots=(managed_root,),
        run=run,
    )
    assert result.exit_code == RUNTIME_DEGRADED
    assert all(command[1] == "show" for command in calls)
    assert external_unit.is_file() and worker_unit.is_file()


def test_cli_purge_removes_only_explicit_child_of_owned_data_root(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        "red2pr_cli.commands._uninstall_services",
        lambda *_args: CliResult(OK, "Red2PR services would be removed."),
    )
    root = tmp_path / "red2pr-data"
    target = root / "cache"
    target.mkdir(parents=True)
    (target / "disposable.tmp").write_text("test", encoding="utf-8")
    env = {"RED2PR_DATA_DIRECTORY": str(root)}

    preview = execute_command(
        "uninstall", args=("--purge", "--path", str(target), "--dry-run"), environ=env
    )
    assert preview.exit_code == OK
    assert "services would be removed" in preview.output.lower()
    assert target.is_dir()

    denied_without_service_confirmation = execute_command(
        "uninstall",
        args=("--purge", "--path", str(target), "--confirm-purge"),
        environ=env,
    )
    assert denied_without_service_confirmation.exit_code == USAGE_OR_CONFIG
    assert target.is_dir()

    removed = execute_command(
        "uninstall",
        args=("--purge", "--path", str(target), "--confirm-purge", "--confirm-uninstall"),
        environ=env,
    )
    assert removed.exit_code == OK
    assert not target.exists()

    outside = execute_command(
        "uninstall",
        args=(
            "--purge",
            "--path",
            str(tmp_path),
            "--confirm-purge",
            "--confirm-uninstall",
        ),
        environ=env,
    )
    assert outside.exit_code == USAGE_OR_CONFIG


def test_cli_mutations_require_csrf_before_network_call() -> None:
    called = False

    def http_call(*_):
        nonlocal called
        called = True
        return 200, b"{}"

    result = execute_command(
        "backup", environ={"RED2PR_API_URL": "https://control.example"}, http_call=http_call
    )
    assert result.exit_code == AUTH_OR_STEP_UP
    assert called is False


def test_cli_logs_are_local_bounded_and_redacted(tmp_path) -> None:
    log_root = tmp_path / "logs"
    log_root.mkdir()
    log_file = log_root / "control.log"
    log_file.write_text(
        "Authorization: Bearer abcdefghijklmnop\npassword=very-secret\n", encoding="utf-8"
    )
    result = execute_command(
        "logs", environ={"RED2PR_LOG_FILE": str(log_file), "RED2PR_LOG_DIRECTORY": str(log_root)}
    )
    assert result.exit_code == 0
    assert "57tfdezo" not in result.output
    assert "abcdefghijklmnop" not in result.output


def test_cli_rotate_secrets_uses_owner_scoped_existing_contract() -> None:
    calls = []
    result = execute_command(
        "rotate-secrets",
        environ={
            "RED2PR_API_URL": "https://red2pr.invalid",
            "RED2PR_WORKSPACE_ID": "workspace-a",
            "RED2PR_SESSION_COOKIE": "session=x",
            "RED2PR_CSRF_TOKEN": "csrf",
        },
        http_call=lambda *args: calls.append(args) or (200, b"{}"),
    )
    assert result.exit_code == 0
    assert (
        calls[0][0]
        == "https://red2pr.invalid/api/v1/workspaces/workspace-a/security/secrets/rotate"
    )


def test_cli_restore_dry_run_never_starts_restore() -> None:
    calls = []
    result = execute_command(
        "restore",
        args=("--backup-id", "019a0000-0000-7000-8000-000000000001", "--dry-run"),
        environ={
            "RED2PR_API_URL": "https://red2pr.invalid",
            "RED2PR_SESSION_COOKIE": "session=x",
            "RED2PR_CSRF_TOKEN": "csrf",
        },
        http_call=lambda *args: (
            calls.append(args)
            or (
                200,
                b'{"backup_id":"019a0000-0000-7000-8000-000000000001",'
                b'"manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
                b'"plan_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",'
                b'"compatible":true}',
            )
        ),
    )
    assert result.exit_code == OK
    assert len(calls) == 1
    assert calls[0][0].endswith("/api/v1/system/restore/dry-run")


def test_cli_restore_requires_exact_fresh_plan_digest_before_execute() -> None:
    calls = []
    plan = (
        b'{"backup_id":"019a0000-0000-7000-8000-000000000001",'
        b'"manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        b'"plan_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",'
        b'"compatible":true}'
    )
    env = {
        "RED2PR_API_URL": "https://red2pr.invalid",
        "RED2PR_SESSION_COOKIE": "session=x",
        "RED2PR_CSRF_TOKEN": "csrf",
    }
    args = (
        "--backup-id",
        "019a0000-0000-7000-8000-000000000001",
        "--confirm-manifest-digest",
        "a" * 64,
        "--confirm-plan-digest",
        "c" * 64,
    )
    mismatch = execute_command(
        "restore", args=args, environ=env, http_call=lambda *call: calls.append(call) or (200, plan)
    )
    assert mismatch.exit_code != OK
    assert len(calls) == 1
    assert calls[0][0].endswith("/api/v1/system/restore/dry-run")

    calls.clear()
    exact = execute_command(
        "restore",
        args=(*args[:-1], "b" * 64),
        environ=env,
        http_call=lambda *call: (
            calls.append(call)
            or ((200, plan) if len(calls) == 1 else (200, b'{"state":"succeeded"}'))
        ),
    )
    assert exact.exit_code == OK
    assert len(calls) == 2
    assert calls[1][0].endswith("/api/v1/system/restore")
    assert calls[1][1] == "POST"


def test_cli_install_checks_setup_state_instead_of_misreporting_status() -> None:
    calls = []
    result = execute_command(
        "install",
        environ={"RED2PR_API_URL": "https://red2pr.invalid", "RED2PR_SESSION_COOKIE": "s=x"},
        http_call=lambda *call: calls.append(call) or (200, b'{"phase":"ready"}'),
    )
    assert result.exit_code == OK
    assert calls[0][0].endswith("/api/v1/setup")
    assert calls[0][1] == "GET"
