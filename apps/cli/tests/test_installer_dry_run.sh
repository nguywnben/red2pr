#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
TEST_DIR="$(mktemp -d /tmp/red2pr-installer-test.XXXXXX)"
cleanup() {
  case "$TEST_DIR" in
    /tmp/red2pr-installer-test.*) rm -rf -- "$TEST_DIR" ;;
    *) printf 'refusing to remove unexpected test path: %s\n' "$TEST_DIR" >&2; return 1 ;;
  esac
}
trap cleanup EXIT

mkdir -p -- "$TEST_DIR/deploy"
cp -R -- "$ROOT/deploy/install" "$ROOT/deploy/security" "$ROOT/deploy/compose" "$TEST_DIR/deploy/"
python3 - "$TEST_DIR" <<'PY'
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

root = Path(sys.argv[1])
key = Ed25519PrivateKey.generate()
(root / "test-private.pem").write_bytes(
    key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
)
(root / "test-public.pem").write_bytes(
    key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
)
images = {
    name: f"registry.example.invalid/red2pr/{name}@sha256:{character * 64}"
    for name, character in (
        ("control", "a"),
        ("worker", "b"),
        ("database", "c"),
        ("redis", "d"),
        ("caddy", "e"),
    )
}
manifest = {
    "schema_version": 1,
    "version": "1.0.0-rc.1",
    "artifacts": [
        {
            "name": "red2pr-cli-test",
            "kind": "cli",
            "url": "https://releases.example.invalid/red2pr-cli-test",
            "sha256": "f" * 64,
        }
    ],
    "images": [{"name": name, "reference": reference} for name, reference in images.items()],
    "minimums": {
        "linux": {"architectures": ["x86_64"], "cpus": 1, "ram_bytes": 536870912, "disk_bytes": 1073741824},
        "macos": {"architectures": ["arm64"], "major_version": 15, "cpus": 1, "ram_bytes": 536870912, "disk_bytes": 1073741824},
        "windows": {"architectures": ["x86_64"], "build": 22000, "cpus": 1, "ram_bytes": 536870912, "disk_bytes": 1073741824},
    },
}
(root / "draft.json").write_text(json.dumps(manifest), encoding="utf-8")
test_install = root / "deploy" / "install"
(test_install / "trust-root.pub").write_bytes((root / "test-public.pem").read_bytes())
(test_install / "trust-root.revoked").write_text("", encoding="ascii")
PY

INSTALLER="$TEST_DIR/deploy/install/install.sh"
MANIFEST="$TEST_DIR/release-manifest.json"
SIGNATURE="$TEST_DIR/release-manifest.sig"
SIGNER="$TEST_DIR/deploy/security/sign_release.py"
chmod 700 "$INSTALLER"
python3 "$SIGNER" sign --input "$TEST_DIR/draft.json" --key "$TEST_DIR/test-private.pem" --output "$MANIFEST" --signature "$SIGNATURE"
"$INSTALLER" --manifest "$MANIFEST" --signature "$SIGNATURE" --verify-only

mkdir -p -- "$TEST_DIR/test-bin"
cat >"$TEST_DIR/test-bin/podman" <<'SH'
#!/bin/sh
case "${1:-}" in
  info) [ "${RED2PR_TEST_RUNTIME_FAIL:-0}" != 1 ] ;;
  compose) exit 1 ;;
  --version) printf 'podman version 4.9.3\n' ;;
  *) exit 0 ;;
esac
SH
chmod 700 "$TEST_DIR/test-bin/podman"
export PATH="$TEST_DIR/test-bin:/tmp/testdeps/bin:$PATH"
export PYTHONPATH="/tmp/testdeps${PYTHONPATH:+:$PYTHONPATH}"

for mode in local worker; do
  data_dir="/var/lib/red2pr/installer-dryrun-${mode}-$$"
  [[ ! -e "$data_dir" ]] || { printf 'test data path already exists: %s\n' "$data_dir" >&2; exit 1; }
  "$INSTALLER" --mode "$mode" --data-dir "$data_dir" --manifest "$MANIFEST" --signature "$SIGNATURE" --dry-run
  [[ ! -e "$data_dir" ]] || { printf 'dry-run created data: %s\n' "$data_dir" >&2; exit 1; }
done

read -r http_port https_port <<<"$(python3 - <<'PY'
import socket
ports = []
for _ in range(2):
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    ports.append(probe.getsockname()[1])
    probe.close()
print(*ports)
PY
)"
server_data_dir="/var/lib/red2pr/installer-dryrun-server-$$"
RED2PR_HTTP_PORT="$http_port" RED2PR_HTTPS_PORT="$https_port" \
  "$INSTALLER" --mode server --data-dir "$server_data_dir" --manifest "$MANIFEST" --signature "$SIGNATURE" --dry-run
[[ ! -e "$server_data_dir" ]] || { printf 'server dry-run created data: %s\n' "$server_data_dir" >&2; exit 1; }

mac_data_dir="$TEST_DIR/mac-data"
RED2PR_INSTALL_TESTING=1 RED2PR_INSTALL_TEST_OS=macos \
  RED2PR_INSTALL_TEST_ARCH=arm64 RED2PR_INSTALL_TEST_OS_VERSION=15 \
  RED2PR_INSTALL_TEST_CPUS=4 RED2PR_INSTALL_TEST_RAM_BYTES=8589934592 \
  RED2PR_INSTALL_TEST_DISK_BYTES=21474836480 \
  "$INSTALLER" --mode local --data-dir "$mac_data_dir" --manifest "$MANIFEST" --signature "$SIGNATURE" --dry-run
[[ ! -e "$mac_data_dir" ]] || { printf 'macOS dry-run created data: %s\n' "$mac_data_dir" >&2; exit 1; }

RED2PR_TEST_RUNTIME_FAIL=1 \
  "$INSTALLER" --mode local --data-dir "/var/lib/red2pr/installer-runtime-failure-$$" --manifest "$MANIFEST" --signature "$SIGNATURE" --dry-run && {
    printf 'unready container runtime was accepted\n' >&2
    exit 1
  }

port=48173
python3 -c 'import socket,sys,time; s=socket.socket(); s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(); time.sleep(30)' "$port" &
listener_pid=$!
trap 'kill "$listener_pid" 2>/dev/null || true; cleanup' EXIT
sleep 0.2
if RED2PR_HTTP_PORT="$port" \
  "$INSTALLER" --mode local --data-dir "/var/lib/red2pr/installer-port-failure-$$" --manifest "$MANIFEST" --signature "$SIGNATURE" --dry-run; then
  printf 'conflicting host port was accepted\n' >&2
  exit 1
fi
kill "$listener_pid" 2>/dev/null || true

cp -- "$MANIFEST" "$TEST_DIR/signed-manifest.backup"
python3 - "$MANIFEST" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
document = json.loads(path.read_text(encoding="utf-8"))
document["version"] = "1.0.0-rc.2"
path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
if "$INSTALLER" --manifest "$MANIFEST" --signature "$SIGNATURE" --verify-only; then
  printf 'tampered release manifest was accepted\n' >&2
  exit 1
fi
mv -- "$TEST_DIR/signed-manifest.backup" "$MANIFEST"

key_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["key_id"])' "$MANIFEST")"
printf '%s\n' "$key_id" >"$TEST_DIR/deploy/install/trust-root.revoked"
if "$INSTALLER" --manifest "$MANIFEST" --signature "$SIGNATURE" --verify-only; then
  printf 'revoked release key was accepted\n' >&2
  exit 1
fi
: >"$TEST_DIR/deploy/install/trust-root.revoked"

if "$INSTALLER" --mode local --data-dir / --manifest "$MANIFEST" --signature "$SIGNATURE" --dry-run; then
  printf 'protected root data directory was accepted\n' >&2
  exit 1
fi

printf 'installer signed-manifest, topology and macOS dry-runs, port/runtime negatives, tamper, revoke, and path-guard tests passed\n'
