# Hosted installation re-verification sweeps

SynSec exposes `runSynSecHostedInstallationReverificationSweep()` and `SynSecHostedInstallationReverificationSweepController` for hosting environments that need to periodically refresh the user-access proof behind hosted GitHub installation ownership.

This is an orchestration and observability boundary, not an authorization boundary. A completed sweep, a scheduler invocation, a zero-failure result, or process-local controller status must never replace `isSynSecHostedInstallationFreshlyAuthorized()` on an installation-scoped request path.

## Trusted inputs

The caller owns `SynSecHostedInstallationReverificationTargetProvider`.

- `listTargets()` must derive the current target set from trusted hosted tenant state. Repository content, webhook payloads, setup URL parameters, account/login strings, or externally supplied metadata are not acceptable target authority by themselves.
- `createTransport(target)` owns the user-scoped GitHub credential boundary. It should obtain a freshly usable credential for only that target and return a transport with bounded GitHub HTTP timeouts/retries.
- SynSec never accepts the credential itself, persists the transport, or serializes transport/backend errors in sweep output.

The sweep validates every principal and installation id, rejects duplicate tenant/installation pairs before requesting credentials, bounds one sweep to 10,000 targets, and bounds concurrency to 1-32 workers.

## Multi-replica behavior

The process-local controller coalesces overlapping `runOnce()` calls only inside one process. It is not a distributed scheduler lock.

Multiple replicas may still execute the same target concurrently. Safety comes from the durable monotonically increasing verification epoch in the ownership store: an older positive or negative completion cannot overwrite a newer observation. Operators may still use leader election or one dedicated scheduler replica to avoid unnecessary GitHub traffic, but leader-election success is not security evidence.

## Failure behavior

Per-target failures are counted in the aggregate `failed` field. Raw GitHub, secret-manager, database, tenant, token, and transport diagnostics are not returned. Target-discovery failure aborts the sweep with the categorical error `Hosted installation re-verification target discovery failed.` because there is no trustworthy bounded target set to process.

A transient per-target failure does not manufacture revocation. Durable authorization continues to rely on the existing freshness deadline: once the last successful verification becomes too old, the request-time authorization gate fails closed.

The sweep intentionally does not implement a synthetic timeout by racing and abandoning `reverifySynSecHostedGitHubInstallation()`. An abandoned promise can still complete remote work and a fenced durable write after the caller thinks it timed out. The credential-owning GitHub transport must therefore enforce real HTTP cancellation/time limits at its own boundary.

## Aggregate observability

A sweep result contains only:

- total attempted targets;
- verified count;
- revoked count;
- superseded count;
- failed count; and
- the interpretation `scheduler-observation-only-not-authorization-evidence`.

It deliberately omits tenant ids, installation ids, GitHub user ids, account names, credential metadata, and backend diagnostics.

`controller.status()` is process-local operational state only. It reports whether one local sweep is active, the number of completed local sweeps, and the last aggregate result. It carries the interpretation `process-local-scheduler-status-only`.

## Service-manager patterns

A systemd timer, Kubernetes CronJob, queue-driven maintenance worker, or application-owned scheduler can invoke `runOnce()` at an operator-selected cadence. The cadence should be comfortably shorter than the request-time freshness maximum so one transient failure does not immediately deny hosted access, while repeated failures still age into a fail-closed authorization state.

For Kubernetes or horizontally scaled services, prefer a single scheduler deployment or external leader election for load control, while preserving the durable epoch fence because scheduler exclusivity can fail during failover.

Monitoring should alert on aggregate failure/revocation trends and on freshness-denied authorization at the request boundary. Do not treat scheduler liveness alone as proof that GitHub access was refreshed.
