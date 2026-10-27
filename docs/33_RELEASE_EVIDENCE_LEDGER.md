# 1.0.0 release evidence ledger — required artifact and signoff

**Status:** TEMPLATE ONLY. No code, tests, or releases are asserted completed by the existence of this file.

## Provenance
| Field | Required evidence |
|---|---|
| Version, git tag and immutable commit SHA | Signed/annotated tag, release commit |
| Code provenance | Repo, commit history, change log, reviewed commits |
| Build provenance | Reproducible CI jobs, image/package digests, dependency lockfiles, SBOM |
| Deployment artifacts | Windows, macOS, Linux installer signatures and hashes; tested OS versions |
| Database migration | Upgrade/downgrade/backup compatibility notes and logs |
| Official vendor compatibility | Live Meta model capability, GitHub App, GitLab webhook, Telegram support matrix |

## Gate matrix (all required for full v1.0.0 claim)
| Gate ID | Evidence required | Outcome initially |
|---|---|---|
| R-01 | Every P0 feature ID mapped to implementation/API/UI/tests and tested | NOT RUN |
| R-02 | GitHub CI failure → red→green → draft PR → remote CI | NOT RUN |
| R-03 | GitLab CI failure → red→green → draft MR → remote CI | NOT RUN |
| R-04 | Meta Muse real API diagnosis/patch with limits, failures and costs | NOT RUN |
| R-05 | Isolated sandbox hostile code tests, no keys/host escape / network egress | NOT RUN |
| R-06 | Auth/RBAC/tenant isolation, SSRF, webhook replay, injection test matrix | NOT RUN |
| R-07 | Queue crash/restart/reconcile, stuck lease, duplicate PR tests | NOT RUN |
| R-08 | Telegram/in-app/SMTP/Slack/Discord/signed webhook delivery tests | NOT RUN |
| R-09 | Linux/macOS/Windows installer on clean supported systems and setup wizard | NOT RUN |
| R-10 | Backup→disaster restore→upgrade→rollback drill on supported matrix | NOT RUN |
| R-11 | React 19/Vite/TypeScript/Astryx UI E2E, a11y and cross-browser tests | NOT RUN |
| R-12 | Benchmark including known failures, abstention and false-green checks | NOT RUN |
| R-13 | Monitoring/alerts/runbooks, maintenance and resource limit tests | NOT RUN |
| R-14 | Dependency vulnerability, secret scan, SBOM, signing, licensing review | NOT RUN |
| R-15 | Documentation, support/limitations, privacy, changelog and operator acceptance | NOT RUN |

Each result must record `test_case_id`, `commit_sha`, `runner_version`, `environment`, `timestamp_UTC`, `command`, `actual_exit_code`, `artifact_uri_or_path`, `human_reviewer`, `status`, `exception_approval`. No generic “tests pass” statements. An `exception_approval` cannot bypass prohibited safety guarantees; scope-restricted releases must be labeled clearly as such, not unconditional 1.0.0.

## Final sign-off and release policy
- Release 1.0.0 is permitted only when every applicable gate passes on published support matrix, all critical security risks closed, owner acknowledges known limitations and release artifacts are verified.
- On failed tests: repair within approved scope, rerun affected suites and independent regression; no new roadmap invented in lieu of fixing defects. If blocked by external credentials/hardware/permissions, record exact blocker and required human action; **never produce a fabricated “ready for production” conclusion**.
- Production readiness is a factual conclusion supported by evidence, not a tone/style preference of final answer.

## P2 trace and exception record
Use [38](38_REQUIREMENTS_TRACEABILITY.md) for forward/reverse mapping and [37](37_NFR_AND_RECOVERY.md) for measured-target records. Every gate above remains NOT RUN. Document lint/link/coverage checks are **not R-01 PASS**, which additionally requires implementation and tests.
High exception fields: finding ID, original severity/reachability, affected build digest/scope, business rationale, compensating control and its test proof, remediation owner, expiry, security reviewer, release owner, retest trigger. Critical/invariant exception rejected. Proposed maximum30days requires ADR-036 approval; expiry automatically blocks next release/renewal until explicitly re-reviewed. Runtime vulnerability alerts require containment/revoke guidance even after release.


[← Mục lục đặc tả](00_INDEX.md) · [Quyết định](20_DECISIONS_ADR.md) · [Truy vết](38_REQUIREMENTS_TRACEABILITY.md)
