# Vision, value and scope

## Product statement
**Red2PR** is a self-hosted **autonomous CI failure investigation and evidence-backed repair platform**. Input: failed CI runs/jobs from GitHub/GitLab. Output: accurate classification, reproduction evidence, a patch within the permitted scope, verification and a transparent draft PR/MR, followed by remote CI monitoring.

## Personas and buyers
- Solo developer / maintainer: shorten the time CI stays red, avoid complex infrastructure and install through one command.
- Engineering lead / DevOps: manage multiple repositories, per-repository policies, reliability and throughput.
- Security / platform admin: control data, permissions, costs, sandboxes, workers, audits and lifecycle operations.
- Reviewer: inspect the cause, proof and patch, then decide whether to merge in the provider.

## Core jobs-to-be-done
1. Connect GitHub/GitLab securely; select repositories, branches and modes.
2. Ingest failures; rule out transient or unrepairable issues instead of forcing a patch.
3. Persist workflows across restarts, retries and duplicate webhooks.
4. Reproduce at the exact SHA in a controlled environment and retain a fidelity report.
5. Patch code/configuration, verify red→green and regression results, and reject test tampering.
6. Create a draft PR/MR with supporting evidence, monitor remote validation and leave review to the user.
7. Observe cost, latency and success; alert through Telegram/email and administer through the dashboard/CLI.

## Differentiators that must be demonstrated
- **Proof package:** baseline failure, patched outcome, artifact hashes, command, image digest, limitations.
- **Correct abstention:** recognize credential, outage, infrastructure, flaky and unsupported cases; do not generate unjustified patches.
- **Operationally self-hosted:** wizard, authentication, lifecycle, safety, backups, monitoring and support matrix.

## UX principles
- Clear installation: begin with one command **when system prerequisites are met**, then complete setup in the browser.
- Safe defaults: Monitor Only for new repositories, draft PRs, no merge and finite budgets.
- Progressive disclosure: a concise overview with detailed evidence available when needed.
- Every mutation has actor, time, reason, irreversible-warning, audit ID.

## Non-goals
- Do not replace GitHub/GitLab or the original CI runner.
- Do not merge, release or deploy to production autonomously.
- Do not promise repairs for every language, runner, integration or private pipeline requiring secrets.
- Do not turn Telegram into an uncontrolled authorization channel.
- Do not treat LLM hallucinations as evidence; camera/voice capabilities are not required.

## Hackathon context
Meta Muse supplies reasoning and patch proposals; deterministic modules enforce policy and run tests. Hackathon checkpoints matter but do not establish production readiness. Keep benchmarks and demonstrations truthful.

## P2 product contract
1.0.0 serves teams with multiple workspaces per self-hosted instance (ADR-030), with explicit repository grants and isolated execution. “Repair with proof” means diagnosis grounded in immutable CI evidence, confirmed baseline, bounded patch, independent verification, policy-authorized draft PR/MR and separate remote-CI verdict. No baseline reproduction means diagnosis/human handling only (ADR-031). Self-hosted control/data custody does not imply offline Meta inference; owner outbound consent remains mandatory. No reduction to chatbot/demo/MVP or removal of production capabilities is authorized.


[← Specification index](00_INDEX.md) · [Decisions](20_DECISIONS_ADR.md) · [Traceability](38_REQUIREMENTS_TRACEABILITY.md)
