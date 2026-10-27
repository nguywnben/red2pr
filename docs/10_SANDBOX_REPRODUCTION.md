# Sandbox, isolation, reproduction fidelity

## Threat assumption
Executing arbitrary project scripts and dependency installers is **untrusted code execution**. Single-host OCI is useful for trusted developer repo workflows but must not be sold as hostile multi-tenant security. Separate worker host/VM is required for untrusted repositories; evaluate gVisor/Firecracker or equivalent defense in depth. Deny workload if isolation requirements are not satisfied.

## Security invariants
- No host Docker socket, privileged containers, host PID/IPC, host network, writable sensitive mounts or control plane credentials.
- Rootless/non-root, read-only root filesystem when feasible, seccomp/AppArmor/SELinux, no-new-privileges, capability drop, user namespaces, resource limits CPU/mem/PIDs/disk/io/time/network.
- Worker isolated from PostgreSQL/Redis/metadata service/provider write tokens/model API keys; immutable/ephemeral filesystem; egress blocked for execution phase by default.
- Dependency restore/installation can execute hooks: run even bootstrap phase in sandbox with registry proxy/network allowlists and content hashes.
- Checkout repo from sanitized immutable archive or read-only short-lived fetch broker; never untrusted `.git` hooks on host. Symlink/path traversal extraction validated.
- Each job includes lease fencing, image digest, command, expected SHA, env manifest, artifact hashes, quotas, execution duration.

## Reproduction pipeline
1. Resolve failed job metadata: OS, image, language version, package lock, service dependencies, matrix parameters, relevant env **without secrets**.
2. Select a supported runner profile from registry; unsupported job => explicit `UNSUPPORTED_PROFILE`.
3. Create sandbox A with immutable source SHA, deterministic dependency lock and profile; run targeted reproduction command.
4. If baseline fails with matching fingerprint/test, classify `REPRO_CONFIRMED`; else `REPRO_UNCONFIRMED`, capture environmental mismatch/fidelity.
5. Create sandbox B from identical baseline image/environment with patch applied; re-run target and configured regressions. Never reuse mutated baseline container.
6. Persist signed or integrity-checkable evidence bundle, cleanup both sandboxes, report orphan cleanup results.

## Fidelity grades (not a fake probability)
- `F1_TARGETED`: same SHA, target test, language runtime; CI runner differences documented.
- `F2_APPROX`: matching Linux runtime & declared services, lockfiles, env nonsecret, matrix; excludes opaque provider actions.
- `F3_VALIDATED`: CI environment reproduction under documented compatibility and equivalent scripts/settings; **not identical production**.
- `FX_UNSUPPORTED`: required platform/secret/peripheral/network not reproducible; do not assert verified.

## Runner profiles
| Profile | Typical workload | Notes |
|---|---|---|
| `python-pytest-linux` | pip/uv/poetry and pytest | pinned image/lock; default no external services |
| `node-jest-linux` | npm/pnpm/yarn and Jest | lockfile fidelity, test-only command |
| `node-vitest-linux` | Vite/Vitest | dedicated config detection |
| `custom-linux-declared` | reviewed manifest | admin opt-in + isolated worker tier |

macOS/Windows job recreation, GPU, Docker-in-Docker, private infra, privileged CI actions, production secrets or deploy steps **are not guaranteed support**. Production release support matrix is explicit; no hidden best effort labeled verified.

## Observability and cleanup
Worker heartbeats and host health; bounded artifact sizes; stdout and stderr streamed via broker with backpressure and redaction; evidence retained by workspace policy; orphan sweeper runs after crashes. Auto-stop jobs on cancel, quota hit, expired token or host health degradation. No direct terminal/shell to untrusted worker from browser without explicit audited debug mode.

## Acceptance
Adversarial fixtures prove worker cannot reach forbidden host networks or secrets; kill/timeout/disk-full leaves no orphaned sensitive state; same command with identical env on baseline vs patch; audit captures image hashes and environment deviations.

## P2 isolation and fidelity acceptance
SAN-01 is the P0 isolation baseline for all supported tenants. SAN-04 P1 adds advanced fleet/backend profiles; it does not defer a mandatory trust boundary (ADR-034 PROPOSED). A hostile job requires separate ephemeral VM or a dedicated worker trust domain isolated from control plane; rootless Docker reduces privileges but does not create a separate kernel. gVisor is an option to validate, not proof of escape immunity.
Two clean environments A/B use identical pinned image/architecture, sourcebase, dependency lock + resolved digests, runtime versions, command/profile, seed, locale/timezone, relevant nonsecret variables, service versions and network policy. B adds only accepted patch. Record all deviations; cache keyed workspace/profile/dependency digest and mounted read-only, never reuse writable cache across trust domains. Baseline logs/results immutable and not patchable by agent.
Dependencies install inside isolated guest with constrained registry egress, credentials absent; lifecycle hooks remain untrusted. Execution phase deny egress by default. Any required service is isolated disposable fixture, never production database. Undeclared service/private secret/custom privileged runtime produces unsupported/human outcome. Archive extraction enforces file count, expanded bytes, path traversal/symlink/hardlink/device restrictions. Disk/memory/PID/CPU/time caps enforced independently of guest process.
F1_TARGETED proves only selected failure under documented approximation; F2_APPROX records material divergence and cannot claim full CI parity; F3_VALIDATED requires the reviewed profile's equivalence checklist; FX_UNSUPPORTED prevents automatic publication. Publication needs V-06 pass under approved minimum fidelity, otherwise human handling without unverified draft. A successful test process with zero expected tests, increased skip/xfail count, altered harness or unrelated failure fingerprint cannot satisfy baseline or green.
Result/signature/upload/lease/cancel protocol is S-21/22 in [36](36_CANONICAL_CONTRACTS.md). Cleanup confirmed by supervisor and tested after crash; failed cleanup quarantines worker, never recycled to next tenant. R-05 checks guest cannot reach model broker, publisher, signing keys, metadata endpoints or control store.


[← Mục lục đặc tả](00_INDEX.md) · [Quyết định](20_DECISIONS_ADR.md) · [Truy vết](38_REQUIREMENTS_TRACEABILITY.md)
