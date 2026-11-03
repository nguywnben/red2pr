# Contributing to Red2PR

Thank you for your interest in Red2PR. Red2PR is built contract-first with strict trust-boundary, accessibility, and deterministic verification requirements.

## Before You Start

1. Read [README.md](README.md), [docs/00_INDEX.md](docs/00_INDEX.md), [docs/05_SYSTEM_ARCHITECTURE.md](docs/05_SYSTEM_ARCHITECTURE.md), [docs/14_SECURITY_IDENTITY.md](docs/14_SECURITY_IDENTITY.md), and [docs/20_DECISIONS_ADR.md](docs/20_DECISIONS_ADR.md).
2. **License (`Apache-2.0`, `ADR-052`):** Red2PR is licensed under the [Apache License, Version 2.0](LICENSE). Under Section 5 of the Apache License 2.0, any contribution intentionally submitted for inclusion is licensed under the same terms without additional conditions.
3. **Never include secrets:** Do not paste real API keys, GitHub App private keys, GitLab tokens, Telegram tokens, or customer logs into issues, tests, fixtures, or commits.

## Monorepo Structure

| Path | Stack | Responsibility |
|---|---|---|
| `packages/py-contracts` | Python 3.12 + Pydantic v2 | Canonical typed schemas (`S-01`–`S-22`) & Ed25519/AEAD crypto primitives. |
| `contracts/` | OpenAPI 3.1 & JSON Schema | Canonical `openapi.v1.json`, `s21-sandbox-worker.v1.schema.json`, and deterministic fixtures. |
| `packages/ts-client` | TypeScript | Generated OpenAPI client, cursor helpers, and `Problem+JSON` error types. |
| `apps/control-plane` | Python 3.12 + FastAPI + SQLAlchemy 2 / Alembic | `Z1` control plane & `Z2` brokers (IAM, RLS DB, triage, Meta Muse inference, verifier, approvals, Draft PR publisher, MCP/Telegram). |
| `apps/worker-supervisor` | Python 3.12 (zero `control-plane` imports) | `Z3` isolated sandbox supervisor (`oci_rootless`, `gvisor`, `microvm` profiles). |
| `apps/cli` | Python 3.12 | Unified `red2pr` operator CLI & installer contract tests. |
| `apps/web` | React 19 + TypeScript + Vite + Meta Astryx `0.7.4` | 21-screen operator & developer web console (`UI-S01`–`UI-S21`). |
| `deploy/` & `scripts/` | Compose, Shell, PowerShell, Python | Signed release manifest tooling, Compose stacks, and one-command local quickstart. |

## Local Development Setup

Prerequisites: Python `3.12.x`, [`uv`](https://docs.astral.sh/uv/), Node.js `>= 22.12.0`, and `pnpm` `9.15.9`.

```bash
# Install Python & frontend workspace dependencies
uv sync --frozen
pnpm install --frozen-lockfile

# Run non-destructive quickstart preflight & disposable smoke test
./scripts/quickstart.sh --check-only
./scripts/quickstart.sh --smoke-test
```

(On Windows PowerShell, use `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\quickstart.ps1 -CheckOnly` and `-SmokeTest`.)

## Required Quality Gates Before Opening a PR

All changes must preserve `Z1`/`Z2`/`Z3` boundaries, OpenAPI parity, strict typing, and WCAG accessibility:

```bash
# Python lint, strict typing, and architecture import boundaries
uv run ruff check .
uv run mypy apps/control-plane/src apps/worker-supervisor/src apps/cli/src packages/py-contracts/src
uv run lint-imports

# Python unit, contract, and targeted integration suites
uv run pytest packages/py-contracts/tests apps/control-plane/tests/contract apps/control-plane/tests/unit apps/worker-supervisor/tests apps/cli/tests/test_installer_contracts.py -q

# Frontend & TypeScript client lint, typecheck, tests, and production bundle
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

## Architectural Guardrails

- **Do not weaken safety gates:** Never bypass `V-01`–`V-08` verification, `SEC-031` workflow hazard checks, `ADR-037` egress validation, PostgreSQL RLS, or TOTP step-up requirements.
- **Contract-first updates:** Any public API DTO change must keep `contracts/openapi/openapi.v1.json`, `apps/control-plane/contracts/openapi/openapi.v1.json`, and `packages/ts-client` in exact parity (`test_openapi_roundtrip.py`).
- **Frontend design system:** Use pinned `@astryxdesign/core@0.7.4` and `@astryxdesign/theme-neutral@0.7.4` wrappers in `apps/web/src/shared/ui/`. Never run `astryx init` at the repository root or overwrite root `AGENTS.md`.
