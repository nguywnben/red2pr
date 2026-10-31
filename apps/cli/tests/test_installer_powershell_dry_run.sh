#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
TEST_DIR="$(mktemp -d /tmp/red2pr-powershell-installer-test.XXXXXX)"
cleanup() {
  case "$TEST_DIR" in
    /tmp/red2pr-powershell-installer-test.*) rm -rf -- "$TEST_DIR" ;;
    *) printf 'refusing to remove unexpected test path: %s\n' "$TEST_DIR" >&2; return 1 ;;
  esac
}
trap cleanup EXIT

mkdir -p -- "$TEST_DIR/deploy"
cp -R -- "$ROOT/deploy/install" "$ROOT/deploy/security" "$ROOT/deploy/compose" "$TEST_DIR/deploy/"
chmod 700 "$TEST_DIR/deploy/install/install.sh"
python3 - "$TEST_DIR" <<'PY'
import json, sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

root = Path(sys.argv[1])
key = Ed25519PrivateKey.generate()
(root / "private.pem").write_bytes(key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
))
(root / "public.pem").write_bytes(key.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
))
images = {
    name: f"registry.example.invalid/red2pr/{name}@sha256:{char * 64}"
    for name, char in (("control", "a"), ("worker", "b"), ("database", "c"), ("redis", "d"), ("caddy", "e"))
}
draft = {
    "schema_version": 1,
    "version": "1.0.0-rc.1",
    "artifacts": [{"name": "red2pr-cli", "kind": "cli", "url": "https://releases.example.invalid/cli", "sha256": "f" * 64}],
    "images": [{"name": name, "reference": reference} for name, reference in images.items()],
    "minimums": {
        "linux": {"architectures": ["x86_64"], "cpus": 1, "ram_bytes": 536870912, "disk_bytes": 1073741824},
        "macos": {"architectures": ["arm64"], "major_version": 15, "cpus": 1, "ram_bytes": 536870912, "disk_bytes": 1073741824},
        "windows": {"architectures": ["x86_64"], "build": 22000, "cpus": 1, "ram_bytes": 536870912, "disk_bytes": 1073741824},
    },
}
(root / "draft.json").write_text(json.dumps(draft), encoding="utf-8")
install = root / "deploy" / "install"
(install / "trust-root.pub").write_bytes((root / "public.pem").read_bytes())
(install / "trust-root.revoked").write_text("", encoding="ascii")
PY

INSTALL_DIR="$TEST_DIR/deploy/install"
MANIFEST="$TEST_DIR/manifest.json"
SIGNATURE="$TEST_DIR/manifest.sig"
python3 "$TEST_DIR/deploy/security/sign_release.py" sign \
  --input "$TEST_DIR/draft.json" --key "$TEST_DIR/private.pem" \
  --output "$MANIFEST" --signature "$SIGNATURE"

mkdir -p -- "$TEST_DIR/bin"
cat >"$TEST_DIR/bin/podman" <<'SH'
#!/bin/sh
case "${1:-}" in
  info) exit 0 ;;
  compose) exit 1 ;;
  --version) printf 'podman version 4.9.3\n' ;;
  *) exit 0 ;;
esac
SH
cat >"$TEST_DIR/bin/wsl.exe" <<'SH'
#!/bin/sh
case "${1:-}" in
  --status) exit 0 ;;
  --list)
    if [ "${2:-}" = --quiet ]; then printf 'Ubuntu\n'; else printf '  NAME      STATE    VERSION\n* Ubuntu    Stopped  2\n'; fi
    ;;
  --exec)
    shift
    if [ "${1:-}" = wslpath ]; then printf '%s\n' "$3"; exit 0; fi
    exec "$@"
    ;;
  *) exit 2 ;;
esac
SH
chmod 700 "$TEST_DIR/bin/podman" "$TEST_DIR/bin/wsl.exe"
cat >"$TEST_DIR/mock-windows.ps1" <<'PS'
param([string]$Installer, [string]$Manifest, [string]$Signature, [string]$DataDir)
$env:ProgramData = '/tmp/red2pr-test-programdata'
$env:windir = '/tmp/red2pr-test-windows'
$env:ProgramFiles = '/tmp/red2pr-test-programfiles'
function Get-CimInstance {
    param([string]$ClassName, [string]$Filter)
    switch ($ClassName) {
        'Win32_OperatingSystem' { return [pscustomobject]@{ BuildNumber = '22631' } }
        'Win32_ComputerSystem' { return [pscustomobject]@{ SystemType = 'x64-based PC'; NumberOfLogicalProcessors = 4; TotalPhysicalMemory = 8589934592L } }
        'Win32_LogicalDisk' { return [pscustomobject]@{ FreeSpace = 21474836480L } }
        default { throw "unexpected CIM query: $ClassName" }
    }
}
& $Installer -Mode local -DataDir $DataDir -Manifest $Manifest -Signature $Signature -DryRun
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
PS

export PATH="$TEST_DIR/bin:/tmp/testdeps/bin:/usr/local/bin:/usr/bin:/bin:/opt/microsoft/powershell/7-lts"
export PYTHONPATH="/tmp/testdeps"
export HOME=/tmp/red2pr-powershell-home
export XDG_CACHE_HOME=/tmp/red2pr-powershell-cache
export XDG_CONFIG_HOME=/tmp/red2pr-powershell-config
export ProgramData=/tmp/red2pr-test-programdata
export windir=/tmp/red2pr-test-windows
export ProgramFiles=/tmp/red2pr-test-programfiles
pwsh -NoProfile -File "$TEST_DIR/mock-windows.ps1" \
  "$INSTALL_DIR/install.ps1" "$MANIFEST" "$SIGNATURE" \
  /var/lib/red2pr/windows-installer-dryrun >"$TEST_DIR/powershell-dry-run.log" 2>&1
cat "$TEST_DIR/powershell-dry-run.log"
grep -Fq 'Dry run passed; no files, services, or host settings changed.' "$TEST_DIR/powershell-dry-run.log" || {
  printf 'PowerShell dry-run did not reach the POSIX compose preflight\n' >&2
  exit 1
}

checkpoint_dir=/var/lib/red2pr/windows-installer-checkpoint-test
set +e
env -u PATH PATH=/usr/local/bin:/usr/bin:/bin:/opt/microsoft/powershell/7-lts pwsh -NoProfile -File "$INSTALL_DIR/install.ps1" \
  -Mode local -DataDir "$checkpoint_dir" -Manifest "$MANIFEST" -Signature "$SIGNATURE"
first_exit=$?
env -u PATH PATH=/usr/local/bin:/usr/bin:/bin:/opt/microsoft/powershell/7-lts pwsh -NoProfile -File "$INSTALL_DIR/install.ps1" \
  -Mode local -DataDir "$checkpoint_dir" -Manifest "$MANIFEST" -Signature "$SIGNATURE" -Resume
resume_exit=$?
set -e
[[ "$first_exit" == 3 && "$resume_exit" == 3 && -f "$checkpoint_dir/install-state.json" ]] || {
  printf 'missing WSL2 checkpoint behavior failed (first=%s resume=%s)\n' "$first_exit" "$resume_exit" >&2
  exit 1
}
python3 - "$checkpoint_dir/install-state.json" "$MANIFEST" <<'PY'
import hashlib, json, sys
from pathlib import Path
checkpoint = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert checkpoint["phase"] == "needs_restart"
assert checkpoint["manifest_sha256"] == hashlib.sha256(Path(sys.argv[2]).read_bytes()).hexdigest()
PY
rm -rf -- "$checkpoint_dir"
printf 'PowerShell Windows mock dry-run and idempotent WSL2 reboot checkpoint tests passed\n'
