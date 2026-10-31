#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
DEPLOY_DIR="$(cd -- "$SCRIPT_DIR/../compose" && pwd -P)"
SECURITY_DIR="$(cd -- "$SCRIPT_DIR/../security" && pwd -P)"
MODE=local
DATA_DIR="${RED2PR_DATA_DIR:-}"
MANIFEST="${RED2PR_RELEASE_MANIFEST:-$SCRIPT_DIR/release-manifest.json}"
SIGNATURE="${RED2PR_RELEASE_SIGNATURE:-$SCRIPT_DIR/release-manifest.sig}"
DRY_RUN=0
VERIFY_ONLY=0
RESUME=0

fail() { printf 'red2pr installer: %s\n' "$*" >&2; exit 2; }
needs_restart() { printf 'red2pr installer: needs_restart: %s\n' "$*" >&2; exit 3; }

while (($#)); do
  case "$1" in
    --mode) (($# >= 2)) || fail '--mode requires local, server, or worker'; MODE="$2"; shift 2 ;;
    --data-dir) (($# >= 2)) || fail '--data-dir requires a path'; DATA_DIR="$2"; shift 2 ;;
    --manifest) (($# >= 2)) || fail '--manifest requires a path'; MANIFEST="$2"; shift 2 ;;
    --signature) (($# >= 2)) || fail '--signature requires a path'; SIGNATURE="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --verify-only) VERIFY_ONLY=1; shift ;;
    --resume) RESUME=1; shift ;;
    -h|--help)
      cat <<'EOF'
Usage: install.sh [--mode local|server|worker] [--data-dir PATH]
                  [--manifest PATH] [--signature PATH]
                  [--dry-run|--verify-only] [--resume]
The installer verifies the offline Ed25519 release manifest before network access,
image pulls, service starts, or filesystem changes. It never installs a container
runtime or changes host firewall/security settings.
EOF
      exit 0
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ "$MODE" == local || "$MODE" == server || "$MODE" == worker ]] || fail 'unsupported mode'
[[ -f "$MANIFEST" && -f "$SIGNATURE" ]] || fail 'signed release manifest and detached signature are required'
command -v openssl >/dev/null || fail 'OpenSSL 3 is required for offline signature verification'
OPENSSL_VERSION="$(openssl version)"
[[ "$OPENSSL_VERSION" == OpenSSL\ 3.* ]] || fail 'OpenSSL 3 is required for offline signature verification'
command -v python3 >/dev/null || fail 'Python 3.12 is required for strict manifest validation'
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' || fail 'Python 3.12 or newer is required for strict manifest validation'

TRUST_ROOT="$SCRIPT_DIR/trust-root.pub"
REVOKED_KEYS="$SCRIPT_DIR/trust-root.revoked"
[[ -f "$TRUST_ROOT" ]] || fail 'pinned offline trust root is missing'
MANIFEST_KEY_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["key_id"])' "$MANIFEST")" || fail 'manifest key identifier is missing'
TRUST_KEY_ID="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$TRUST_ROOT")"
[[ "$MANIFEST_KEY_ID" == "$TRUST_KEY_ID" ]] || fail 'manifest key identifier does not match the pinned trust root'
if [[ -f "$REVOKED_KEYS" ]] && awk '!/^[[:space:]]*#/ && NF {print $1}' "$REVOKED_KEYS" | grep -Fxq "$MANIFEST_KEY_ID"; then
  fail 'release signing key is revoked'
fi
python3 "$SECURITY_DIR/sign_release.py" validate --input "$MANIFEST" >/dev/null || fail 'manifest schema validation failed'
openssl pkeyutl -verify -rawin -pubin -inkey "$TRUST_ROOT" -in "$MANIFEST" -sigfile "$SIGNATURE" >/dev/null 2>&1 || fail 'release signature verification failed'
printf 'Verified signed release manifest (key %s).\n' "${MANIFEST_KEY_ID:0:12}"

if ((VERIFY_ONLY)); then
  exit 0
fi

MOCK_OS="${RED2PR_INSTALL_TEST_OS:-}"
if [[ -n "$MOCK_OS" ]]; then
  [[ "$DRY_RUN" == 1 && "${RED2PR_INSTALL_TESTING:-}" == 1 ]] || fail 'mock OS probes are only available in explicit test dry-runs'
  OS_NAME="$MOCK_OS"
  ARCH="${RED2PR_INSTALL_TEST_ARCH:-}"
  OS_VERSION="${RED2PR_INSTALL_TEST_OS_VERSION:-}"
  CPU_COUNT="${RED2PR_INSTALL_TEST_CPUS:-}"
  RAM_BYTES="${RED2PR_INSTALL_TEST_RAM_BYTES:-}"
  DISK_BYTES="${RED2PR_INSTALL_TEST_DISK_BYTES:-}"
  [[ -n "$ARCH" && -n "$CPU_COUNT" && -n "$RAM_BYTES" && -n "$DISK_BYTES" ]] || fail 'mock OS probe values are incomplete'
else
  case "$(uname -s)" in
    Linux)
      # shellcheck disable=SC1091
      OS_NAME="$(. /etc/os-release 2>/dev/null; printf '%s' "${ID:-unknown}")"
      ARCH="$(uname -m)"
      # shellcheck disable=SC1091
      OS_VERSION="$(. /etc/os-release 2>/dev/null; printf '%s' "${VERSION_ID:-0}")"
      CPU_COUNT="$(getconf _NPROCESSORS_ONLN)"
      RAM_BYTES="$(awk '/MemTotal:/ {printf "%.0f\n", $2 * 1024}' /proc/meminfo)"
      ;;
    Darwin)
      OS_NAME=macos
      ARCH="$(uname -m)"
      OS_VERSION="$(sw_vers -productVersion | cut -d . -f 1)"
      CPU_COUNT="$(sysctl -n hw.physicalcpu)"
      RAM_BYTES="$(sysctl -n hw.memsize)"
      ;;
    *) fail 'supported hosts are Ubuntu/Debian Linux or macOS 15+ ARM64' ;;
  esac
  if [[ -z "$DATA_DIR" ]]; then
    case "$OS_NAME" in
      linux|ubuntu|debian) DATA_DIR=/var/lib/red2pr ;;
      macos) DATA_DIR="$HOME/Library/Application Support/Red2PR" ;;
      *) fail "unsupported operating system: $OS_NAME" ;;
    esac
  fi
  DISK_PATH="$DATA_DIR"
  while [[ ! -e "$DISK_PATH" && "$DISK_PATH" != / && "$DISK_PATH" != . ]]; do DISK_PATH="$(dirname -- "$DISK_PATH")"; done
  if [[ "$OS_NAME" == macos ]]; then
    DISK_BYTES="$(df -Pk "$DISK_PATH" | awk 'NR==2 {printf "%.0f\n", $4 * 1024}')"
  else
    DISK_BYTES="$(df -P -B1 "$DISK_PATH" | awk 'NR==2 {printf "%.0f\n", $4}')"
  fi
fi

case "$OS_NAME" in
  ubuntu|debian|linux) PROFILE_OS=linux ;;
  macos) PROFILE_OS=macos ;;
  *) fail "unsupported operating system: $OS_NAME" ;;
esac

if ((RESUME)); then
  [[ -f "$DATA_DIR/install-state.json" ]] || fail 'no installer checkpoint exists to resume'
  python3 - "$DATA_DIR/install-state.json" "$MANIFEST" "$MODE" "$DATA_DIR" <<'PY'
import hashlib, json, pathlib, sys
checkpoint = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
manifest_digest = hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()
if checkpoint.get("phase") != "needs_restart" or checkpoint.get("manifest_sha256") != manifest_digest:
    raise SystemExit("installer checkpoint does not match this signed manifest")
if checkpoint.get("mode") != sys.argv[3] or checkpoint.get("data_dir") != str(pathlib.Path(sys.argv[4]).resolve()):
    raise SystemExit("installer checkpoint arguments changed; restart installation explicitly")
PY
fi

CANONICAL_DATA_DIR="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$DATA_DIR")"
case "$PROFILE_OS:$CANONICAL_DATA_DIR" in
  linux:/|linux:/root|linux:/home|linux:/etc|linux:/usr|linux:/var|linux:/opt|linux:/tmp|linux:/root/*|linux:/home/*|linux:/etc/*|linux:/usr/*|linux:/var/*|linux:/opt/*|linux:/tmp/*)
    [[ "$CANONICAL_DATA_DIR" == /var/lib/red2pr || "$CANONICAL_DATA_DIR" == /var/lib/red2pr/* ]] || fail 'data directory resolves to a protected system path'
    ;;
  macos:/|macos:/System|macos:/System/*|macos:/Applications|macos:/Applications/*|macos:/Library|macos:/Library/*|macos:"$HOME"|macos:"$HOME/Library")
    fail 'data directory resolves to a protected system path'
    ;;
esac

case "$OS_NAME" in
  linux|ubuntu|debian)
    [[ "$OS_NAME" == ubuntu || "$OS_NAME" == debian ]] || fail 'supported Linux installers require Ubuntu or Debian'
    ;;
  macos)
    [[ "$OS_VERSION" =~ ^[0-9]+$ && "$OS_VERSION" -ge 15 ]] || fail 'macOS 15 or newer is required'
    ;;
  *) fail "unsupported operating system: $OS_NAME" ;;
esac
case "$ARCH" in x86_64|aarch64|arm64) : ;; *) fail "unsupported CPU architecture: $ARCH" ;; esac

MINIMUMS="$(RED2PR_INSTALL_OS="$PROFILE_OS" python3 - "$MANIFEST" <<'PY'
import json, os, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
profile = doc["minimums"][os.environ["RED2PR_INSTALL_OS"]]
print(profile["cpus"], profile["ram_bytes"], profile["disk_bytes"], " ".join(profile["architectures"]), profile.get("major_version", 0))
PY
)"
read -r MIN_CPUS MIN_RAM MIN_DISK SUPPORTED_ARCHES MIN_OS_VERSION <<<"$MINIMUMS"
case "$ARCH" in x86_64) ARCH_ALIAS=x86_64 ;; aarch64|arm64) ARCH_ALIAS=arm64 ;; esac
[[ " $SUPPORTED_ARCHES " == *" $ARCH_ALIAS "* ]] || fail "release does not support architecture $ARCH_ALIAS"
if [[ "$OS_NAME" == macos && "$OS_VERSION" -lt "$MIN_OS_VERSION" ]]; then
  fail "release requires macOS $MIN_OS_VERSION or newer"
fi
((CPU_COUNT >= MIN_CPUS)) || fail "host requires at least $MIN_CPUS CPUs"
((RAM_BYTES >= MIN_RAM)) || fail "host requires at least $MIN_RAM bytes of memory"
((DISK_BYTES >= MIN_DISK)) || fail "filesystem requires at least $MIN_DISK free bytes"

case "$MODE" in
  local) COMPOSE_FILE="$DEPLOY_DIR/compose.local.yml" ;;
  server) COMPOSE_FILE="$DEPLOY_DIR/compose.server.yml" ;;
  worker) COMPOSE_FILE="$DEPLOY_DIR/compose.distributed-worker.yml" ;;
esac
if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
  RUNTIME=(docker)
elif command -v podman >/dev/null && podman compose version >/dev/null 2>&1; then
  COMPOSE=(podman compose)
  RUNTIME=(podman)
elif command -v podman-compose >/dev/null; then
  COMPOSE=(podman-compose)
  RUNTIME=(podman)
else
  fail 'Docker Compose v2 or podman-compose is required; installer will not install a runtime'
fi
"${RUNTIME[@]}" info >/dev/null 2>&1 || fail 'container runtime is installed but not ready; start it and rerun the installer'

case "$MODE" in
  local) REQUIRED_PORTS="${RED2PR_HTTP_PORT:-8080}/tcp" ;;
  server) REQUIRED_PORTS="${RED2PR_HTTP_PORT:-80}/tcp ${RED2PR_HTTPS_PORT:-443}/tcp ${RED2PR_HTTPS_PORT:-443}/udp ${RED2PR_BOOTSTRAP_PORT:-18080}/tcp" ;;
  worker) REQUIRED_PORTS= ;;
esac
if [[ -n "$REQUIRED_PORTS" ]]; then
  python3 - "$REQUIRED_PORTS" <<'PY' || fail 'one or more required host ports are already in use'
import socket, sys
for entry in sys.argv[1].split():
    raw_port, protocol = entry.split("/", 1)
    family = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    probe = socket.socket(socket.AF_INET, family)
    try:
        probe.bind(("0.0.0.0", int(raw_port)))
    except OSError:
        raise SystemExit(1)
    finally:
        probe.close()
PY
fi

while IFS=$'\t' read -r NAME REPOSITORY DIGEST; do
  case "$NAME" in
    control) export RED2PR_CONTROL_REPOSITORY="$REPOSITORY" RED2PR_CONTROL_DIGEST="$DIGEST" ;;
    worker) export RED2PR_WORKER_REPOSITORY="$REPOSITORY" RED2PR_WORKER_DIGEST="$DIGEST" ;;
    database) export RED2PR_DATABASE_REPOSITORY="$REPOSITORY" RED2PR_DATABASE_DIGEST="$DIGEST" ;;
    redis) export RED2PR_REDIS_REPOSITORY="$REPOSITORY" RED2PR_REDIS_DIGEST="$DIGEST" ;;
    caddy) export RED2PR_CADDY_REPOSITORY="$REPOSITORY" RED2PR_CADDY_DIGEST="$DIGEST" ;;
  esac
done < <(python3 - "$MANIFEST" <<'PY'
import json, sys
for image in json.load(open(sys.argv[1], encoding="utf-8"))["images"]:
    repository, digest = image["reference"].split("@sha256:", 1)
    print(f"{image['name']}\t{repository}\t{digest}")
PY
)
export RED2PR_CONFIG_FILE="${RED2PR_CONFIG_FILE:-$CANONICAL_DATA_DIR/config/config.yaml}"
export RED2PR_DATABASE_URL_FILE="${RED2PR_DATABASE_URL_FILE:-$CANONICAL_DATA_DIR/secrets/database_url}"
export RED2PR_POSTGRES_PASSWORD_FILE="${RED2PR_POSTGRES_PASSWORD_FILE:-$CANONICAL_DATA_DIR/secrets/postgres_password}"
export RED2PR_REDIS_PASSWORD="${RED2PR_REDIS_PASSWORD:-dry-run-only}"
export RED2PR_CADDYFILE="$DEPLOY_DIR/Caddyfile"
if [[ "$MODE" == server && "$DRY_RUN" != 1 ]]; then
  [[ "${RED2PR_FQDN:-}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || fail 'server mode requires a valid RED2PR_FQDN before issuing TLS setup links'
else
  RED2PR_FQDN="${RED2PR_FQDN:-red2pr.invalid}"
fi
export RED2PR_FQDN
export RED2PR_CONTROL_URL="${RED2PR_CONTROL_URL:-https://127.0.0.1:8443}"
export RED2PR_WORKER_CERT_DIR="${RED2PR_WORKER_CERT_DIR:-$CANONICAL_DATA_DIR/worker-certs}"
export RED2PR_WORKER_NETWORK="${RED2PR_WORKER_NETWORK:-red2pr-mtls-egress}"
export RED2PR_BOOTSTRAP_ISSUER_SECRET="${RED2PR_BOOTSTRAP_ISSUER_SECRET:-dry-run-only}"

if ((DRY_RUN)); then
  printf 'Preflight: mode=%s data_dir=%s os=%s arch=%s cpu=%s memory=%s\n' "$MODE" "$CANONICAL_DATA_DIR" "$OS_NAME" "$ARCH_ALIAS" "$CPU_COUNT" "$RAM_BYTES"
  if [[ "${COMPOSE[0]}" == podman-compose ]]; then
    "${COMPOSE[@]}" -f "$COMPOSE_FILE" config >/dev/null
  else
    "${COMPOSE[@]}" -f "$COMPOSE_FILE" config --quiet
  fi
  printf 'Dry run passed; no files, services, or host settings changed.\n'
  exit 0
fi

for required in RED2PR_CONFIG_FILE RED2PR_DATABASE_URL_FILE RED2PR_POSTGRES_PASSWORD_FILE RED2PR_REDIS_PASSWORD; do
  [[ -n "${!required:-}" ]] || fail "required deployment setting is missing: $required"
done
[[ -f "$RED2PR_CONFIG_FILE" && -f "$RED2PR_DATABASE_URL_FILE" && -f "$RED2PR_POSTGRES_PASSWORD_FILE" ]] || fail 'configuration and secret files must be provisioned before installation'
VERSION="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])' "$MANIFEST")"
mkdir -p -- "$CANONICAL_DATA_DIR/releases"
RELEASE_DIR="$CANONICAL_DATA_DIR/releases/$VERSION"
if [[ -d "$RELEASE_DIR" ]]; then
  while IFS=$'\t' read -r NAME DIGEST; do
    [[ -f "$RELEASE_DIR/$NAME" && ! -L "$RELEASE_DIR/$NAME" ]] || fail "staged release is incomplete: $NAME"
    python3 - "$DIGEST" "$RELEASE_DIR/$NAME" <<'PY' || fail "staged artifact digest mismatch: $NAME"
import hashlib, pathlib, sys
actual = hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()
if actual != sys.argv[1]: raise SystemExit(1)
PY
  done < <(python3 - "$MANIFEST" <<'PY'
import json, sys
for artifact in json.load(open(sys.argv[1], encoding="utf-8"))["artifacts"]: print(f"{artifact['name']}\t{artifact['sha256']}")
PY
)
else
  STAGE_DIR="$(mktemp -d "$CANONICAL_DATA_DIR/.release-${VERSION}.XXXXXX")"
  cleanup_stage() { [[ -n "${STAGE_DIR:-}" && -d "$STAGE_DIR" ]] && rm -rf -- "$STAGE_DIR"; }
  trap cleanup_stage EXIT
  while IFS=$'\t' read -r NAME URL DIGEST; do
    case "$NAME" in */*|*\\*|.|..) fail 'unsafe artifact filename' ;; esac
    curl --fail --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --output "$STAGE_DIR/$NAME" "$URL"
    python3 - "$DIGEST" "$STAGE_DIR/$NAME" <<'PY' || fail "artifact digest mismatch: $NAME"
import hashlib, pathlib, sys
digest = hashlib.sha256()
with pathlib.Path(sys.argv[2]).open("rb") as artifact:
    for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
        digest.update(chunk)
if digest.hexdigest() != sys.argv[1]:
    raise SystemExit(1)
PY
  done < <(python3 - "$MANIFEST" <<'PY'
import json, sys
for artifact in json.load(open(sys.argv[1], encoding="utf-8"))["artifacts"]:
    print(f"{artifact['name']}\t{artifact['url']}\t{artifact['sha256']}")
PY
  )
  mv -- "$STAGE_DIR" "$RELEASE_DIR"
  STAGE_DIR=""
fi
ISSUER_SECRET_FILE="$CANONICAL_DATA_DIR/secrets/bootstrap_issuer"
mkdir -p -- "$(dirname -- "$ISSUER_SECRET_FILE")"
if [[ -e "$ISSUER_SECRET_FILE" ]]; then
  [[ -f "$ISSUER_SECRET_FILE" && ! -L "$ISSUER_SECRET_FILE" ]] || fail 'bootstrap issuer secret path is unsafe'
  [[ "$(wc -c < "$ISSUER_SECRET_FILE")" -ge 64 ]] || fail 'bootstrap issuer secret file is malformed'
  chmod 600 "$ISSUER_SECRET_FILE"
else
  openssl rand -hex 32 > "$ISSUER_SECRET_FILE"
  chmod 600 "$ISSUER_SECRET_FILE"
fi
RED2PR_BOOTSTRAP_ISSUER_SECRET="$(cat -- "$ISSUER_SECRET_FILE")"
[[ "$RED2PR_BOOTSTRAP_ISSUER_SECRET" =~ ^[0-9a-f]{64}$ ]] || fail 'bootstrap issuer secret file is malformed'
export RED2PR_BOOTSTRAP_ISSUER_SECRET
if [[ "$MODE" == server ]]; then
  BOOTSTRAP_PORT="${RED2PR_BOOTSTRAP_PORT:-18080}"
  SETUP_BASE_URL="https://${RED2PR_FQDN}"
else
  BOOTSTRAP_PORT="${RED2PR_HTTP_PORT:-8080}"
  SETUP_BASE_URL="http://127.0.0.1:$BOOTSTRAP_PORT"
fi
if [[ "${COMPOSE[0]}" == podman-compose ]]; then
  "${COMPOSE[@]}" -f "$COMPOSE_FILE" config >/dev/null
else
  "${COMPOSE[@]}" -f "$COMPOSE_FILE" config --quiet
fi
"${COMPOSE[@]}" -f "$COMPOSE_FILE" up -d
BOOTSTRAP_URL="http://127.0.0.1:$BOOTSTRAP_PORT"
for attempt in $(seq 1 60); do
  if curl --fail --silent --show-error "$BOOTSTRAP_URL/api/v1/system/health" >/dev/null 2>&1; then break; fi
  ((attempt < 60)) || fail 'control plane did not become healthy within 5 minutes'
  sleep 5
done
BOOTSTRAP_LINK="$(python3 - "$BOOTSTRAP_URL" "$RED2PR_BOOTSTRAP_ISSUER_SECRET" "$SETUP_BASE_URL" <<'PY'
import http.cookiejar, json, sys, urllib.error, urllib.request
base, secret, setup_base = sys.argv[1:]
cookies = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
with opener.open(base + "/api/v1/auth/csrf", timeout=15) as response:
    csrf = json.load(response)
headers = {"Accept":"application/json", "Content-Type":"application/json", "Origin":base,
           "X-CSRF-Token":csrf["csrf_token"], "X-Red2PR-Bootstrap-Issuer":secret}
request = urllib.request.Request(base + "/api/v1/setup/bootstrap-token", data=b"{}", headers=headers, method="POST")
try:
    with opener.open(request, timeout=15) as response: issued = json.load(response)
except urllib.error.HTTPError as error:
    if error.code == 409:
        print("already-claimed")
        raise SystemExit(0)
    raise
from urllib.parse import quote
print(f"{setup_base}/setup#bootstrap_token={quote(issued['bootstrap_token'], safe='')}")
PY
)" || fail 'bootstrap handoff failed'
if [[ "$BOOTSTRAP_LINK" == already-claimed ]]; then
  printf 'Deployment %s is healthy; instance owner is already claimed.\n' "$VERSION"
else
  printf 'Deployment %s is healthy. One-use setup link (expires in 15 minutes): %s\n' "$VERSION" "$BOOTSTRAP_LINK"
fi
