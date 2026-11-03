## Summary
- **Scope / ADR / Feature IDs:**
- **What changed and why:**

## Trust Boundary & Safety Checklist
- [ ] Preserves `Z1` / `Z2` / `Z3` boundaries (`uv run lint-imports` passes; zero control-plane imports in `apps/worker-supervisor`).
- [ ] Does not weaken `V-01`–`V-08` verification, `SEC-031` hazard checks, PostgreSQL RLS, `ADR-037` egress policy, or step-up MFA.
- [ ] OpenAPI (`contracts/openapi/openapi.v1.json`) and `@red2pr/ts-client` remain in parity if any API schema changed.
- [ ] Contains no secrets, tokens, private keys, or unredacted external logs; root `AGENTS.md` is unmodified.

## Verification Evidence
List exact commands executed and exit codes:
- `uv run ruff check .`:
- `uv run mypy ...`:
- `uv run pytest ...`:
- `pnpm lint && pnpm typecheck && pnpm test && pnpm build`:
