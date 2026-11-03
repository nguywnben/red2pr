"""Unit tests for the standalone `red2pr-worker` CLI composition root."""

from __future__ import annotations

from pathlib import Path

import pytest

from red2pr_worker.runtime import main


def test_worker_cli_check_wiring_materializes_signer_and_seccomp(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state_dir = tmp_path / "state"
    scratch_dir = tmp_path / "scratch"
    rc = main(
        [
            "--check-wiring",
            "--state-dir",
            str(state_dir),
            "--scratch-dir",
            str(scratch_dir),
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "wiring verified" in out
    assert (state_dir / "worker_result_ed25519.key").is_file()
    assert (state_dir / "worker_result_ed25519.pub.json").is_file()
    assert (state_dir / "red2pr-seccomp.v1.json").is_file()

    # Idempotent second invocation over read-only seccomp file:
    rc_repeat = main(
        [
            "--check-wiring",
            "--state-dir",
            str(state_dir),
            "--scratch-dir",
            str(scratch_dir),
        ]
    )
    assert rc_repeat == 0


def test_worker_cli_rejects_signer_inside_guest_scratch(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    scratch_dir = tmp_path / "scratch"
    nested_state = scratch_dir / "nested-state"
    rc = main(
        [
            "--check-wiring",
            "--state-dir",
            str(nested_state),
            "--scratch-dir",
            str(scratch_dir),
        ]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "ADR-035 violation" in err


def test_worker_cli_fails_closed_without_mtls_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("RED2PR_WORKER_CERT", raising=False)
    monkeypatch.delenv("RED2PR_WORKER_KEY", raising=False)
    monkeypatch.delenv("RED2PR_WORKER_CA", raising=False)
    monkeypatch.delenv("RED2PR_WORKER_ENROLL_TOKEN", raising=False)
    rc = main(
        [
            "--once",
            "--control-url",
            "https://127.0.0.1:8443",
            "--state-dir",
            str(tmp_path / "state"),
            "--scratch-dir",
            str(tmp_path / "scratch"),
        ]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "mTLS credentials are not provisioned" in err
