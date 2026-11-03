#!/usr/bin/env bash
set -Eeuo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
MODE="up"
PORT="${RED2PR_HTTP_PORT:-4280}"
DATA_DIR="${RED2PR_DATA_DIR:-}"

fail() {
  printf 'red2pr quickstart: %s\n' "$*" >&2
  exit 2
}

while (($#)); do
  case "$1" in
    --check-only) MODE="check"; shift ;;
    --smoke-test) MODE="smoke-test"; shift ;;
    --port) (($# >= 2)) || fail "--port requires a TCP port"; PORT="$2"; shift 2 ;;
    --data-dir) (($# >= 2)) || fail "--data-dir requires a path"; DATA_DIR="$2"; shift 2 ;;
    -h|--help)
      cat <<'EOF'
Usage: ./scripts/quickstart.sh [--check-only|--smoke-test] [--port PORT] [--data-dir PATH]
Starts a local single-origin Red2PR stack (PostgreSQL 16 + FastAPI Control Plane + React/Astryx Web UI)
without overwriting existing data or printing raw secrets.
EOF
      exit 0
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done

cd -- "$REPO_ROOT"
command -v node >/dev/null 2>&1 || fail "Node.js >= 22.12 is required."
command -v pnpm >/dev/null 2>&1 || fail "pnpm is required (corepack enable && corepack prepare pnpm@9.15.9 --activate)."

VENV_PYTHON="$REPO_ROOT/.venv/bin/python"
if [[ ! -x "$VENV_PYTHON" ]]; then
  command -v uv >/dev/null 2>&1 || fail ".venv not found and 'uv' is not installed. Install uv (https://docs.astral.sh/uv/) and rerun."
  printf 'Provisioning Python 3.12 virtual environment via uv sync...\n'
  uv sync --frozen
elif ! "$VENV_PYTHON" -c 'import websockets, pgserver' >/dev/null 2>&1; then
  if command -v uv >/dev/null 2>&1; then
    uv sync --frozen
  fi
fi

if [[ ! -d "$REPO_ROOT/node_modules" ]]; then
  printf 'Installing frontend workspace dependencies via pnpm...\n'
  pnpm install --frozen-lockfile
fi

if [[ "$MODE" != "check" && ! -f "$REPO_ROOT/apps/web/dist/index.html" ]]; then
  printf 'Building Red2PR TypeScript client and React/Astryx web bundle...\n'
  pnpm run quickstart:web
fi

PYTHONPATH="$REPO_ROOT/packages/py-contracts/src:$REPO_ROOT/apps/control-plane/src:$REPO_ROOT/apps/worker-supervisor/src:$REPO_ROOT/apps/cli/src${RED2PR_EXTRA_PYTHONPATH:+:$RED2PR_EXTRA_PYTHONPATH}"
export PYTHONPATH

ARGS=("$REPO_ROOT/scripts/dev_stack.py" "$MODE" "--port" "$PORT")
if [[ -n "$DATA_DIR" ]]; then
  ARGS+=("--data-dir" "$DATA_DIR")
fi
exec "$VENV_PYTHON" "${ARGS[@]}"
