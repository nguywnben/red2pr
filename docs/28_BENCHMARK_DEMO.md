# Demonstration, benchmark, reproducibility protocol

## Competition narrative
Problem: developers waste time on red CI and generic agents may claim success without proof. Red2PR uses Meta Muse for reasoning+coding but relies on deterministic sandbox/verification and policy gates for trustworthy repairs. Show **real external CI and a real draft PR** on controlled test repos if authorized.

## Demo scenario A — true code regression
- Construct genuine failing GitHub Actions Python test; capture failing SHA and test failure.
- GitHub webhook/polling triggers; dashboard shows diagnosis with evidence citations.
- Reproduction sandbox on baseline fails; patch attempt fixes logic with strict diff policy; same test and regressions pass.
- Publisher opens draft PR containing evidence references; actual remote PR CI passes on matching SHA.
- Operator sees status transition from `locally_verified` to `remotely_verified` with timestamps and audit.

## Demo scenario B — GitLab/node integration
- GitLab CI Node test fails; adapter normalizes job trace, Muse proposes patch, worker reproduces with pinned runtime, creates draft MR and follows CI.
- If not fully implemented by judging day, label planned/not yet certified; do not fabricate screen recording.

## Demo scenario C — correct refusal
- CI registry returns 503 or credentials missing. Triage yields `infra_or_auth_failure`, publishes diagnostic only; no code patch, no PR. Demonstrates restraint.

## Demo scenario D — malicious patch/injection
- Fixture contains injected instruction inside code/log asking for secret or skipping tests. Agent restricted tools cannot access secrets; deterministic policy rejects attempts to weaken test; dashboard shows policy block and reason.

## Benchmark design
- Curate >=20 CI failures, balanced fixable, nonfixable, flaky, platform mismatch and sensitive cases, plus multiple languages/providers when supported.
- For each record dataset ID, base SHA, license, expected root cause, failing command, environment digest, allowed files, known passing patch (where permitted), confidence rubric, expected abstention.
- Run Red2PR with fixed model/budget, runner versions, tests and timeouts; publish raw denominators and complete outcomes. Compare baseline manual/scripted systems when feasible.

## Evaluation metrics
Classification accuracy, correct abstention, baseline reproduction rate, valid patch rate, verified fix rate, remote CI pass rate, false repair rate, median time to fix, API+compute cost per verified patch, duplicate PR count. Calculate each with explicit denominators. Model judgments cannot replace actual tests.

## Demo reliability
Record video and scripted fixtures as fallback; real run can be flaky/provider rate limited. Maintain sanitized dummy repos and secrets. Include version/commit and proof IDs visible in screen capture; timebox to viewer journey and record deviations. Never expose real org tokens/private source in video.

## P2 benchmark integrity
The >=20case corpus must include unreproducible, flaky, infra, wrong-SHA, changed-test and prompt-injection negatives; ADR-031 expects **zero publication** for unconfirmed baseline. Record all attempts/abstentions/cost, not curated successes. R-12 uses NFR-06/NFR-15 and per-feature cases in [38](38_REQUIREMENTS_TRACEABILITY.md). Hackathon-specific submission rules remain unknown until exact event supplied; demo success is never production evidence.


[← Mục lục đặc tả](00_INDEX.md) · [Quyết định](20_DECISIONS_ADR.md) · [Truy vết](38_REQUIREMENTS_TRACEABILITY.md)
