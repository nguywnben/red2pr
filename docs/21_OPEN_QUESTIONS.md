# Open questions, assumed defaults, vendor constraints

| ID | Open issue | Safe interim assumption | How to resolve before implementation/release |
|---|---|---|---|
| OQ-01 | Meta API account has Muse Spark/Wonder availability, tool/JSON support and limits? | Spark primary; feature probe, no Wonder guarantee | live access check + official docs; record model IDs |
| OQ-02 | GitHub App permissions to edit workflow YAML, forks and visibility? | workflow file edits protected, reviewed only | GitHub permission reference + integration test |
| OQ-03 | GitLab signing token, project/group-level API version differences? | verify per supported GitLab version | supported GitLab test matrix and API doc |
| OQ-04 | Docker Desktop licensing/WSL2/reboot requirement? | installer warns and guides | OS/enterprise policy evaluation and tests |
| OQ-05 | Final Linux/macOS/Windows versions and RAM footprint? | do not advertise broad matrix | performance benchmark, QA hardware |
| OQ-06 | Default isolation for remote multi-tenant customer repos? | separate worker VM mandatory | independent security review and threat testing |
| OQ-07 | Required GDPR/privacy region and Meta inference retention? | explicit owner consent per repo | provider terms, privacy counsel if selling B2B |
| OQ-08 | Telegram bot per instance vs shared SaaS bot? | per-instance operator-managed bot | licensing/support/secure identity design |
| OQ-09 | Public relay availability/business model? | optional future module, disabled | security and cost review |
| OQ-10 | Formal SLO/support contract? | none until benchmark | production measurement and owner decisions |
| OQ-11 | Product license, third-party obligations, use of pre-existing code? | new repo, attribution tracking, no unlicensed code reuse | legal/license review |
| OQ-12 | Hackathon rules/eligibility/new code requirements? | do not assume prior work allowed or all features required | read current Official Rules, record accepted terms |
| OQ-13 | Multi-workspace/OIDC/SAML product tiering? | one instance with workspace RBAC model, SSO P1 | customer needs and scope sign-off |
| OQ-14 | Require public accessibility for judge demo vs video? | prepare safely accessible demo test repo | submission portal and participant guide official text |
| OQ-15 | Fixed default repair budget/file/line limits? | bounded configurable defaults, not calibrated | trial corpus and stress metrics |
| OQ-16 | Model fallback policy for outage and non-Meta providers? | no silent cross-provider fallback | explicit tenant opt-in/security consent |
| OQ-17 | Worker host provisioning UX across three OS? | local trusted + server isolated profile | QA lab and security docs |
| OQ-18 | Retention/backup and artifact quotas? | safe bounded defaults, user policy | cost/security/business needs |
| OQ-19 | Astryx Beta compatibility, React 19 peer deps and TS imports? | pin tested Astryx release and wrapper API | run official Vite example + a11y/browser suites; record version |
| OQ-20 | Does Astryx CLI init alter root AGENTS.md? | never permit overwrite without merge-review | test in disposable working tree, preserve operating contract |
| OQ-21 | Candidate production v1.0.0 scope and support tiers after product audit? | P0 release required, P1 implemented only if verified; explicit gating | owner signs revised catalog and release matrix |

## Risk register (initial priority)
| Severity | Risk | Mitigation design | Status |
|---|---|---|---|
| Critical | Untrusted repo escapes sandbox | dedicated worker VM, deny sensitive network/creds, adversarial tests | untested |
| Critical | False verified patch / test tampering | deterministic verifier, immutable evidence, negative tests | untested |
| Critical | Provider write tokens leak to agent/worker | broker+publisher boundary, secrets canary | untested |
| High | webhook duplicates create duplicate PRs | intents, stable branch marker, reconcile after timeout | untested |
| High | API/regulatory changes break integrations | adapter contracts + official references + compatibility tests | untested |
| High | self-host installer modifies host unexpectedly | dry-run, signatures, consent, upgrade/restore drills | untested |
| High | huge model/worker costs | budget per repo/session, rate limit, alert | untested |
| Medium | Telegram command impersonation | short-lived web approval with RBAC | untested |
| Medium | Dashboard misreports successful repairs | separated local/remote statuses and denominators | untested |

All statuses are design-stage: **nothing above is implemented/tested**.

## P2 disposition — 2026-10-27
Original table is historical question inventory. Status below resolves it; unknown vendor facts are not owner-choice questions.

| Item | Current disposition | Resolution owner / evidence |
|---|---|---|
| OQ-13 tenancy | **RESOLVED:** multi-workspace1.0.0, ADR-030 | explicit owner answer; OIDC/SSO scope still PROPOSED/P1 |
| Baseline publication | **RESOLVED:** no publication if no confirmed baseline, ADR-031 | explicit owner answer; no policy/human override |
| Security severity | **RESOLVED:** Critical closed, High exception time-bound+mitigation, ADR-032 | explicit owner answer; proposed maximum30days not yet accepted |
| OQ-01/02/03/19/20 | **VERIFIABLE, PARTIAL:** official public sources read; Astryx pinned props inspected | exact account/version/runtime/export/CLI effect requires later authorized tests; [22](22_OFFICIAL_REFERENCES.md) |
| OQ-04/05/17 | **VERIFIABLE:** candidate matrix and prerequisites documented, no machine certifications | OS lab, performance+runtime/license checks; R-05/R-09 |
| OQ-06 | **OWNER REVIEW + VERIFIABLE:** hostile worker separation mandatory design; deployment backend choice ADR-034/035 | approve boundary, then independent security evidence |
| OQ-07/11 | **OWNER CONTEXT + VERIFIABLE:** target customer regions/data classes/license/publishing identity unresolved | owner defines market/license intent; official terms review verifies constraints |
| OQ-08 | **PROPOSED:** per-instance operator bot; no shared SaaS bot assumed | owner approve contract; Telegram docs do not decide commercial tenancy |
| OQ-09 | **OWNER DECISION:** no relay by default; optional P1 preserved | self-operated relay vs operated service has cost/privacy/support implications |
| OQ-10/15/18 | **OWNER REVIEW + MEASUREMENT:** numerical defaults proposed in doc37 | calibrate benchmark; contractual SLA never inferred |
| OQ-12/14 | **OWNER CONTEXT:** exact hackathon/event unspecified; outside B2B readiness gates | identify event only if submission still wanted; cannot search unnamed rules |
| OQ-16 | **PROPOSED:** no silent vendor switch; optional verified model profile | source/cost/consent tests; no new vendor without owner scope |
| OQ-21 | **REVIEW PENDING:** preserve46IDs/41P0/4P1/1P2 | approve v5 specification before any detailed master plan or code |

### Decisions genuinely needed from owner
1. ADR-034: approve local invitations under IAM-02 and mandatory TOTP/step-up for privileged roles (recommended), or retain MFA-ready and supply an explicitly reviewed alternate strong-auth policy. SSO remains P1 unless owner promotes it; no hidden scope reduction.
2. ADR-035/036: approve proposed PostgreSQL/outbox + Redis/Dramatiq + separate supervisor/publisher and target operating envelope, or name constraints that rule it out. Numbers remain targets until measured; High waiver30day cap needs owner sign-off.
3. ADR-021/024: select license/publishing identity and customer region/data-sharing constraints; decide self-host relay only vs operated relay if P1 is included. These are business decisions, not facts a vendor page can settle.

Not deciding these during P2 does not prevent documentation completion. They remain explicit blockers **before affected implementation/design freeze**, not permission to silently choose. P2 spec approval is distinct from permission to execute code or use external resources.


[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
