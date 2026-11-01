# IG-06 local verification evidence

**Status:** PASS — final local verification completed on 2026-11-01.

**Gate scope:** Master Plan `IG-06` (all 46 feature contracts, 21 UI screens, 24 API families, 22 schemas, CLI and installer scripts; deterministic unit, contract, migration, boundary and integration checks).

**Source provenance:** `main` at base commit `75f16730e9f956f253e771bec2c5bc817cbef76c`, plus the code/evidence commit recorded by the follow-up progress entry in `docs/23_PROGRESS.md`. The progress entry is a documentation-only commit; no source changed afterward. No push or merge was performed.

## Environment and safety

- Owner-authorized Red2PR lab host, Linux x86_64; test workloads ran in resource-limited Podman containers.
- Python test runner: Python 3.12, 4 CPU / 4 GiB; test PostgreSQL 16 had a 1 GiB tmpfs data directory, on an internal-only Podman network, with no published ports.
- Frontend and installer checks ran in disposable containers. Frontend package checks used network isolation. PowerShell installer checks used PowerShell 7.4.22 with .NET 8.0.33.
- No live provider, customer IdP, real account, paid API, production database, public listener, deploy, push or merge was used.

## Completed checks

| Check | Command or suite | Actual result |
|---|---|---|
| Complete Python suite | `python -m pytest -q -q` from the repository root (the four configured test roots in `pyproject.toml`) | Exit `0`; 399 test cases reached 100%. The runner emits progress only at double quiet; one non-failing `XDG_RUNTIME_DIR` fallback warning. |
| Python focused boundary regressions | `python -m pytest` over U28 OIDC integration, U26 keyring/backup, U30 migration round-trip, relay/catalog migrations and the four formerly runner-blocked cases | Exit `0`; `26 passed, 1 warning in 63.12s`. Warning was `XDG_RUNTIME_DIR` fallback only. |
| Python strict typing for changed modules | `mypy --strict --cache-dir=/tmp/mypy-ig06` on `core/keyring.py`, `core/secret_ports.py`, `iam/oidc.py`, `operations/backup_restore.py`, `secrets/broker.py`, and `api/app.py` | Exit `0`; `Success: no issues found in 6 source files`. |
| Python lint and formatting | `ruff check .`; `ruff format --check` for the 10 changed Python source/migration/test files | Exit `0`; `All checks passed!`; `10 files already formatted`. |
| Import boundary contracts | `lint-imports` with the project `PYTHONPATH` | Exit `0`; 223 files / 1,919 dependencies; 4 contracts kept, 0 broken. |
| Web/client checks | OpenAPI TypeScript codegen; typed client checks/build/tests; web typecheck, ESLint, Vitest and Vite production build | Exit `0`; client contract suite passed; web: 28 files / 91 tests passed; 2,578 modules transformed. See frontend log. |
| Linux/macOS installer dry runs | `bash apps/cli/tests/test_installer_dry_run.sh` | Exit `0`; Linux local/worker/server plus macOS dry run and runtime/port/signature/revocation/protected-path negative cases passed. |
| Windows installer mock dry run | `bash apps/cli/tests/test_installer_powershell_dry_run.sh` | Exit `0`; PowerShell 7.4.22 Windows mock dry run and idempotent WSL2 reboot checkpoint cases passed. |
| Patch whitespace | `git diff --check` | Exit `0`. |

The first full run reported `395 passed, 4 errors`; these were PostgreSQL fixture setup errors caused by the read-only `pgserver` package. The four affected tests passed in the focused run above with the disposable writable test environment and explicit lab database fixture. A later run exposed a response-order race in the U06 last-admin test (`204 + 404` is valid when the first request revokes the second caller); the test now checks both valid fail-closed response shapes and asserts the database still has exactly one active admin. The corrected test passed in isolation, and the final full suite then exited `0`. The earlier failing log is preserved as `python-ig06-full-before-race-test-fix.log`.

Archived console transcripts have only trailing whitespace normalized; the earlier failure transcript also redacts its ephemeral PostgreSQL URL credentials. Test names, assertions, exit results and failure details remain intact.

## Evidence files

- `frontend-ig06-rerun.log`
- `installer-posix-ig06.log`
- `installer-powershell-ig06.log`
- `python-ig06-final.log` (earlier full run and its fixture errors)
- `python-ig06-full-before-race-test-fix.log` (full run exposing the concurrency assertion mismatch)
- `python-ig06-final-rerun.log` and `python-ig06-final-rerun.exit` (final complete suite, exit `0`)
- `python-last-admin-race-final.log` (corrected concurrency test, `1 passed`)
- `python-db-edge-rerun.log` (four previously fixture-blocked tests)
- `python-boundary-regression-final.log` (focused 26-test final-code run)
- `ig06-boundaries-final.log` (Ruff, format and import-linter output)
- `mypy-boundary-final.log`

## Scope limits

This is local deterministic gate evidence, not release certification or operational validation. Browser journeys, cross-browser/screenshots and full accessibility certification remain in the separately authorized UI redesign / U32 work; no UI redesign was started. No v1.0.0 release gate or production-readiness claim is made.
