# Red2PR — CI Repair with Proof

> **Status:** PRODUCT SPECIFICATION / NOT IMPLEMENTED. These documents are neither product source code nor evidence of production readiness.
>
> **Direction:** A production-first, self-hosted platform for individuals, teams and businesses managing CI repair with Meta Muse AI. **Frontend:** React 19 + TypeScript + Vite + Meta Astryx Design System. **Backend/agents:** Python + FastAPI. The official v1.0.0 release requires evidence that all release gates pass.

Red2PR is designed to ingest CI failures from GitHub Actions/GitLab CI, diagnose their causes, reproduce them in isolated sandboxes, propose and apply patches, verify them with real tests, and open **draft Pull Requests / Merge Requests** with evidence before monitoring remote CI. All side effects pass through policy/approval controls; **no auto-merge**.

## Working rules
- `AGENTS.md` provides safety instructions for coding agents; it is **not a chat prompt**.
- `docs/00_INDEX.md` indexes the complete specification; `docs/20_DECISIONS_ADR.md` records governing decisions.
- Design the whole product first, then implement vertical slices with continuous testing. Do not replace the target scope with a demo or call an untested system production-ready.
- This documentation package contains no API keys, personal information, cloud resources or deployment code.
- The documents are a **specification/contract**, not an instruction to implement everything without testing. Use only Astryx UI components confirmed by official documentation/CLI; the backend remains Python.
- The coding-agent workflow is: ingestion → deep review/spec consolidation → frozen integrated implementation plan → execute the exact approved unit → independently audited release. Operating prompts remain **outside the repository** and are not included in the documentation archive.

## Status and support scope
Every feature in `docs/02_FEATURE_CATALOG.md` is a **target requirement**. Initial release scope, the support matrix and gates are defined in `docs/24_RELEASE_READINESS.md` and `docs/27_SUPPORT_MATRIX.md`. Unresolved issues are tracked in `docs/21_OPEN_QUESTIONS.md` and require verification or an owner decision.

## Documentation
See [docs/00_INDEX.md](docs/00_INDEX.md).

## Specification review P2 — 2026-10-27
Current artifact is a **design under owner review**, not working product code. [Specification index](docs/00_INDEX.md), [before/after audit](docs/39_SPEC_AUDIT.md), [46-feature traceability](docs/38_REQUIREMENTS_TRACEABILITY.md) and [decisions](docs/20_DECISIONS_ADR.md) record the production scope, accepted owner choices, proposed contracts and unverified vendor/runtime dependencies. Frontend remains React19 + TypeScript + Vite + Astryx; backend/agents Python/FastAPI. No implementation master plan or product execution is authorized by this documentation update.
