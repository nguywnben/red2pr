# Release readiness and production support policy

## Ship labels
- `DESIGN_ONLY`: documents exist, no source; **current status**.
- `DEVELOPMENT`: some features implemented, may use mock fixtures.
- `ALPHA`: real end-to-end supported path, limited QA, no external production claim.
- `BETA`: feature complete for declared support matrix, security/ops tests ongoing.
- `PRODUCTION_READY for <scope>`: all gates and owner sign-off pass; support exclusions explicit.

## Mandatory release gates (checklist only after proof)
- [ ] Critical findings in release scope are closed; High findings only with named owner, mitigation, expiry and signed exception (ADR-032). Secret leakage, authorization bypass, cross-workspace leakage, sandbox escape or false-green never qualify for exception.
- [ ] GitHub provider E2E passes webhook and polling, failure->repro->patch->verified->draft PR->remote check.
- [ ] GitLab provider E2E passes pipeline->job trace->repro->patch->verified->draft MR->remote check.
- [ ] Supported Python and Node profiles pass positive/negative tests on isolated workers.
- [ ] Sandbox trust boundaries tested (worker cannot read host secrets/control-plane, enforce resources and egress).
- [ ] Model adapter works with real Meta key, structured output/tool calling and budget/cancel behavior.
- [ ] No false-green for test-skipping/deleting/weakening patches; baseline and remote status never conflated.
- [ ] GitHub/GitLab token management, signed webhook verification, provider rate/revocation tests pass.
- [ ] Auth, admin bootstrap, MFA posture and cross-repo RBAC including Telegram pass security tests.
- [ ] Notification redaction, delivery retry, dedup, callback web confirmation pass.
- [ ] Queue crash recovery, outbox, leases, lost callbacks, duplicate publisher reconcile and upgrades verified.
- [ ] One-command install, upgrade, rollback, doctor, backup + restore tested on each **advertised** OS profile.
- [ ] UI uses pinned React 19 + TypeScript + Vite + Astryx, passes build/typecheck/unit/component/visual/accessibility tests; state/error/permissions and safe artifact display validated.
- [ ] Every P0 feature has requirement→API/UI→test→evidence trace; optional integrations have explicit enable/disable behavior and support declarations.
- [ ] Telegram/email/Slack/Discord/outgoing webhook delivery verified with test accounts, consent, redaction, opt-out, retry/replay safety.
- [ ] Observability: correlation, metrics, alerts and on-call runbook tested.
- [ ] SBOM, dependency/container scanning, pinned images, signed release and secret leak checks completed.
- [ ] User docs/CLI/support matrix/known limitations and data transfer disclosures published.
- [ ] Owner signed dated release checklist with links to test/attack/recovery evidence.

## Release record template
`version`, `git_sha`, `build_provenance`, `supported_os`, `runtime_profiles`, `provider_versions`, `test_suite_results`, `attack_fixture_results`, `backup_restore_drill`, `SLO_measurements`, `known_limitations`, `owner_signoff`. No blanket production claims outside tested matrix.

## Change and vulnerability management
Every release has changelog, migration plan, vulnerability response channel, rollback safety notes and updated release signature/digest. Safe design can be complete before software implementation; production status cannot.


[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
