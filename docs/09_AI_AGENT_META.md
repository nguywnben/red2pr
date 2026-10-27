# AI agentic design + Meta Muse integration

## AI role boundaries
- **Triage:** deterministic signatures first, Muse Spark for nuanced classification; output `fixable|non_fixable|unknown`, confidence treated as uncalibrated.
- **Diagnosis Agent:** scoped repo/code/log search, root-cause hypotheses with evidence pointers, reproduction requests; cannot mutate repo directly.
- **Patch Agent:** code-edit/test loop in cloned sandbox with restricted typed tools; attempts/time/tokens/files/line limits.
- **Verification Engine:** deterministic independent code + attestable worker outputs; NEVER an LLM that certifies itself.
- **PR Reporter:** natural-language explanation derived only from verification manifest and redacted model reasoning; do not invent exact numbers.
- **Orchestrator:** transitions, retry, publication, policy in deterministic code; no autonomous agent swarm coordination for initial release.

## Model adapter
Preferred default from Meta docs: base `https://api.meta.ai/v1`, `muse-spark-1.3`, optionally `muse-wonder-1.0` when tenant access verified. Do not hardcode provider commercial plans/prices or claim availability without a live feature probe. Use strict API adapter exposing capabilities (`tool_calls`, `structured_output`, token usage, streaming, cancellation, limits), errors and telemetry. Support per-tenant model allowlist, region/data-transfer consent and fail-closed policy.

## Agent loop
```text
Orchestrator.load_context(repo, SHA, failure/evidence)
  -> Model.struct_output(root_causes, evidence_refs, proposed reproduction)
  -> Validate schema + authorization + budget
  -> SandboxManager.reproduce(base SHA)
  -> if eligible then PatchAgent.modify restricted worktree
  -> SandboxManager.run(targeted/regression checks)
  -> DeterministicVerifier.grade + policy
  -> if approved/reviewed then Publisher.draftPR
```

## Typed tools & permission matrix
| Tool | Input | Side effect | Permission |
|---|---|---|---|
| `read_file` | canonical repo path, byte bounds | none | read-only |
| `search_repo` | query, path_prefix, max_results (S-20) | none | read-only |
| `read_log_excerpt` | artifact_id, offset, length (S-20) | none | authorized evidence read |
| `read_commit_diff` | immutable SHA/ref | none | read-only |
| `request_reproduction` | profile ID, command preset | new isolated job | approval by orchestrator/policy |
| `apply_patch` | patch_artifact_id, base_sha, expected_worktree_digest | sandbox worktree | path/scope guard |
| `run_targeted_test` | profile_id, test_selection_id, patch_digest | isolated execution | command policy and resource limits |
| `get_execution_result` | operation_id | none | read signed output |

`publish`, `merge`, `rotate_secret`, `run_host_shell`, `send_network_request`, `edit_policy` are never direct agent tools.

## Context and prompt injection defense
- Pull context only for relevant changed files, stack frames, test metadata; secret redact before external inference.
- Source content and CI logs tagged **UNTRUSTED DATA** and have no instruction priority.
- Typed tool JSON validated and risk scored; model tool call can be rejected regardless of model rationale.
- Sanitize embedded markdown/HTML, dangerous links, ANSI logs, binary payloads, Unicode controls; source references anchored to immutable artifact digests.
- Do not rely on prompt injection resistance alone: no sensitive tools in agent environment.

## Model routing and failure policy
- Spark default for triage/simple patch, Wonder as opt-in escalation under cost budget; no silent provider switch to non-Meta by default (especially hackathon).
- On `429` use bounded Retry-After/backoff; auth failure triggers suspended integration; provider outage triggers `suspension.reason=model_unavailable`/`DEGRADED`, never fake success.
- Track total API calls, input/output tokens, cost estimates vs final billed usage; privacy consent required for private repo outbound context.
- Add max per run, per day/workspace/tenant, per model. Cancellation stops further calls and worker requests.

## Schemas, outcomes and evaluation
- `DiagnosisResult`: failure taxonomy, 1..N hypotheses, evidence refs, proposed action, unsupported reasons, uncertainty.
- `PatchProposal`: changed paths, diff hash, claimed root cause, tests to run, potential risk.
- `RepairExplanation`: cause supported by evidence, what changed, red-green results, unverified checks, privacy-safe PR text.
- Evaluate on historical real CI and synthetic mutations; track diagnosis accuracy, eligible abstention, reproducibility, verified-fix rate, remote CI pass, false-green, cost and latency. Regression prompts model-upgrade gated.

## Capability checks
See `docs/22_OFFICIAL_REFERENCES.md`; verify actual Muse model id, limits, tool calling, structured outputs and billing on account at integration setup. Users may configure another compatible provider later, but the Meta-native pipeline remains first-class and auditable.

## P2 agent safety and inference contract
Meta public documentation is **DOC_VERIFIED**, not proof of this account's access. Catalogue observed Muse Spark1.3 and Muse Wonder1.0; Wonder Full is not Model API access. Base endpoint/model IDs in earlier examples are source-observed, not live-tested credentials or quota. Endpoint family/capabilities and limits are snapshots, re-probed only with explicit operator consent/budget. A disabled/unavailable optional model never triggers hidden provider fallback. No offline inference certification is implied by self-hosting or by new open-weight vendor offerings.

| Stage | Required input/output | Abstention / limits |
|---|---|---|
| Classify | immutable run/job/attempt, redacted log refs → S-11 classification with cited evidence and uncertainties | infra/network/auth/unsupported never patch; flaky/unknown needs bounded independent repeated observation, not model confidence |
| Gather context | allowlisted source at SHA, dependency lock, relevant CI profile, failing test, bounded history → hashed context manifest | partial logs/missing dependencies/secret requirement explicit; redact before outbound; owner consent version checked each request |
| Reproduce | supervisor job + baseline failure signature → evidence ref and fidelity grade | unrelated install error is not original regression; baseline green/timeout/missing test exits repro_unconfirmed |
| Patch | confirmed baseline + bounded context → patch artifact and explanation | same base only; scope/line cap and tests semantics inspected outside LLM; denied request cannot expand scope |
| Verify | independent profile-selected original/regression checks → deterministic manifest | model cannot set exit/result/pass, choose fewer mandatory tests, sign manifest or override policy |
| Report | accepted manifest fields → readable draft narrative | narrative never becomes gate input; contradictions with evidence rejected/redrafted |

All tool payloads follow S-20 [36](36_CANONICAL_CONTRACTS.md). Repository instructions/logs/dependency output are quoted untrusted data; any instruction claiming to change system policy is ignored at tool broker boundary. No unrestricted code execution in control process; shell commands resolve from reviewed profile and run only in guest. Agent memory/context caches key workspace/repo/SHA/policy/redaction revision; no cross-workspace embeddings, shared scratch files or tool credentials.

Budget reservation before every outbound request includes max output tokens, input estimate, pricing revision and compute allowance. Atomic per-session/workspace/provider reservations prevent parallel overspend; settlement uses usage response, unknown outcome reserves worst-case until reconciled/manual expiry policy, never records zero. Retry consumes same logical request tracking plus additional potential spend; no assumption vendor honors idempotency. Cancel prevents new requests; already sent inference may finish/bill, recorded as late result, never applied to cancelled worktree.
TARGET defaults proposed: max30 calls,120k total tokens,2 patch attempts,30min session walltime and USD5 estimated cap (owner configurable downward/upward only within workspace hard cap). A missing/unknown price blocks cost-governed execution until configured audited upper bound; dollar cap is Red2PR estimate, not vendor billing guarantee. See NFR-06 and R-04/R-12; no measured success/cost claimed.
Structured-output and tool calling source docs establish API shapes only; host still validates schema and fields, forbids extra args and quarantines invalid tool/result transitions. Persist redacted request/response IDs/hashes and selected model/adapter revision, never require or store hidden chain-of-thought. Evals report correct abstention, false-positive publication, wrong-SHA proofs, prompt-injection/tool-policy violations and cost including failed attempts, not only best successful patches.


[← Mục lục đặc tả](00_INDEX.md) · [Quyết định](20_DECISIONS_ADR.md) · [Truy vết](38_REQUIREMENTS_TRACEABILITY.md)
