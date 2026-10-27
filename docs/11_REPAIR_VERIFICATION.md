# Repair, deterministic verification, approval and PR/MR

## Repair stages
- Triage must decide whether code/config patch is appropriate; don't patch transient network/secret/runner outages automatically.
- Diagnosis hypothesis cites exact immutable evidence refs; no free-form model 'confidence' as proof.
- Patch Agent edits only allowed paths; preserved baseline test semantics; diff and required tests evaluated after each attempt.
- Independent verifier compares baseline and patched run under comparable environments and checks policy.
- Publisher separate from agent has narrow provider write identity; draft PR/MR only, never auto-merge.

## Verification checks
| ID | Gate | Required evidence |
|---|---|---|
| V-01 | Baseline red | SHA, failing command, failure fingerprint, log range |
| V-02 | Patched green | same failure no longer reproduces, result and artifact hashes |
| V-03 | Regression | configured relevant tests pass; number of skipped tests audited |
| V-04 | Integrity | diff paths/size/dependency lock, no unapproved gate weakening |
| V-05 | Security | secrets and sensitive data scans, denied risky capabilities |
| V-06 | Fidelity | env/runtime/image differences and unsupported service dependencies |
| V-07 | Auth/Policy | repo, branch, actor, approval, mode, budget, effective policy revision |
| V-08 | Remote CI | matching PR commit CI conclusion received from provider after publication |

## Evidence vocabulary
`DIAGNOSED_ONLY` ≠ `REPRO_CONFIRMED` ≠ `LOCALLY_VERIFIED` ≠ `REMOTELY_VERIFIED` ≠ `MERGED` (Red2PR does NOT execute merge). ADR-031: a baseline that cannot be reproduced leads to `repro_unconfirmed`, diagnosis and human handoff. Branch creation, push and draft PR/MR publication are prohibited for that session; human approval cannot waive V-01.

## Diff integrity
- No deleting/skip/xfail/suppressing failing tests, lowering lint security gates, modifying workflow to avoid checks, or unexpected deletion of files.
- Test updates may be legitimate when behavior changed intentionally: require reviewer approval + explanation + independent policy check; original issue/test intent retained.
- Changes to `.github/workflows`, `.gitlab-ci.yml`, auth, deploy, dependencies/lockfiles, policies and migrations are sensitive; default `approval` regardless of repo auto mode unless explicit scoped policy.
- Patch size/attempt limits default configurable, never infinite. Cross-file consistent edits permitted if scope and tests support it.

## Publishing flow
1. Verify proof manifest and safe diff; check current repo access and target branch policy.
2. Ensure base SHA still valid; stale ref/force push triggers re-evaluation, no silent force push to developer branch.
3. Create deterministic repair branch under integration identity; store intent before remote side effect.
4. Commit patch, create draft PR/MR, embed generated explanation with exact source evidence IDs and links to authenticated dashboard artifacts.
5. On timeout, reconcile existing branch/PR/MR by marker; do not create duplicates.
6. Monitor provider check suite for actual pushed SHA, including matrix results; remote pass reported separately, errors and awaiting state shown.

## PR summary template fields
`Failure`, `Root cause and uncertainty`, `Why this patch`, `File changes`, `Before/after reproduction` (commands, exit codes), `Regression verification`, `Sandbox fidelity`, `Known limitations`, `Security/policy checks`, `Evidence URL`, `Remote CI status`. Disallow raw secrets/private CI logs in public PR body; use dashboard gated link.

## Approvals
Human approval identity bound to account/workspace/repo/patch digest/policy revision, expires, one-use, audited with actor and reason. If diff changes after approval, approval invalidated. Slack/Telegram reactions alone never perform privileged write without approved web challenge or explicitly reviewed secure delegated auth.

## Failure modes
Inconclusive baseline -> `REPRO_UNCONFIRMED` with human handoff and no publication; flaky baseline -> reruns and abstention; infra issue -> no patch; provider permission revocation -> stop; expired approval -> gate; remote CI fail -> link iteration budget and show new failure classification.


[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
