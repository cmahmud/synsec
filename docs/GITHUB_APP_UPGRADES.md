# GitHub App rolling upgrades and rollback

SynSec's hosted GitHub App has durable shared state and fenced workers, but those properties do not by themselves make an application rollout safe. A production service manager also needs exact fleet membership, fresh runtime observations, closed work admission, drained durable leases, an immutable previous artifact, and an explicit database-schema rollback decision.

`@synsec/github/app-upgrade` provides a secret-free gate for that orchestration boundary. `@synsec/github/app-drain` provides the local enforced webhook-admission primitive, while `@synsec/github/app-worker-drain` provides the separate local background-worker admission primitive. None of these modules restarts processes, mutates PostgreSQL, executes migrations, revokes credentials, or calls a deployment platform.

## Trusted observations

The service manager supplies:

- distinct current and target release identifiers;
- current and target shared-state schema versions;
- the exact expected replica identifiers;
- one fresh observation for every replica containing the loaded release, schema version, readiness, worker-admission state, durable active lease count, and observation timestamp;
- whether the immutable previous release artifact is still deployable; and
- whether a schema change is explicitly rollback-compatible.

Replica observations and `assessedAt` must come from trusted supervisor/runtime state. Repository content, webhook payloads, scanner output, or user-controlled metadata must never be allowed to manufacture these values.

## Enforced local webhook admission drain

Wrap the production webhook handler with `createSynSecGitHubAppDrainController()` before passing it to the GitHub App listener. `beginDrain()` immediately prevents new webhook requests from entering the wrapped handler. Rejected requests receive only an aggregate `503 {"status":"draining"}` response plus `Retry-After: 1`, allowing GitHub to retry without reflecting delivery ids, repositories, payloads, or backend errors.

Requests admitted before the drain continue running. `waitForDrained()` waits only for those in-process webhook calls. `resumeAdmission()` is explicit so a failed rollout can reopen the old replica without recreating the handler.

## Enforced local worker admission drain

Create one `createSynSecGitHubAppWorkerDrainController()` per hosted worker replica and pass it to `runConfiguredGitHubAppWorkerOnce({ workerDrain: controller, ... })`. `beginDrain()` synchronously closes admission. After it returns, a new configured-worker invocation receives `{ status: "draining" }` without reaching `queue.claimNext()`, so it cannot acquire a new durable lease through this worker path.

A worker invocation admitted before `beginDrain()` remains owned by the worker. It is allowed to keep its existing heartbeat, finish publication, and perform the normal fenced terminal transition. The drain controller does not cancel the scanner, steal a lease, rewrite durable state, or force a stale worker to complete.

`activeWorkerRuns` is deliberately only an in-process count of operations admitted through this controller. It is useful for waiting for local admitted work to exit, but it is **not** durable lease evidence and cannot survive a crashed process. `waitForDrained()` therefore also requires worker admission to already be closed, preventing a check-then-claim race inside the local orchestration sequence.

## Durable lease observation remains separate

Closing local worker admission and reaching `activeWorkerRuns === 0` prevents this replica from deliberately starting more work, but fleet-wide replacement still requires the shared transactional backend to report zero active fenced leases for the replica being replaced. Conversely, observing `activeLeases === 0` while worker admission remains open is only a momentary state: a worker could claim another job immediately afterward.

For that reason `assessSynSecGitHubAppUpgrade()` treats a replica as drained only when both are true:

- `acceptingWorkerRuns === false`; and
- `activeLeases === 0` from trusted durable-backend/supervisor observation.

An open worker-admission observation produces `worker-admission-open` and blocks rollout/finalization even when the lease count is zero.

## Start gate

`readyToBeginRollout` is true only when the exact expected fleet is:

- still on the previous release;
- ready;
- closed to new worker runs;
- free of active durable leases;
- represented by fresh observations; and
- rollback-capable.

For schema-changing releases, rollback capability must be an explicit operator/migration property. SynSec does not infer reversibility merely because a migration completed successfully.

A conservative per-replica rolling sequence is:

1. call webhook `beginDrain()` so new GitHub deliveries receive retryable aggregate-only responses;
2. call worker `beginDrain()` so this replica cannot make another queue claim;
3. wait for both local controllers' admitted work to drain;
4. observe the shared fenced durable lease count reach zero and record `acceptingWorkerRuns: false`;
5. run the upgrade assessment with a fresh observation and keep the previous immutable artifact plus compatible database state available;
6. replace that replica with the target release;
7. verify normal readiness and shared-state health, then open admissions on the new replica according to the service-manager policy;
8. continue one replica at a time; and
9. run the final fleet assessment before retiring the previous artifact.

The assessment intentionally treats active durable work or open worker admission as rollout blockers. A deployment platform can choose a different drain policy, but it must not reinterpret this result as proof that interrupting workers is safe.

## Finalization gate

`readyToFinalizeRollout` requires the exact expected fleet to be fresh, ready, closed to new worker admission for the assessment window, free of active durable leases, on the target release, and reporting the target schema version. Old-release replicas, open worker admission, active leases, or target replicas reporting another schema prevent finalization.

Only after finalization should an operator consider removing the previous application artifact. Credential rotation is separate: follow `GITHUB_APP_CREDENTIAL_RELOAD.md` and `GITHUB_APP_CREDENTIAL_RELOAD_FRESHNESS.md` before retiring an old GitHub credential.

## Rollback

`rollbackAllowed` requires the previous immutable application artifact to remain available. If the release changes the database schema, the caller must additionally assert that the target schema is compatible with the previous application release.

This is deliberately conservative. A migration declaration, application readiness probe, or successful target startup is not evidence that an old binary can safely use the new schema. Destructive or one-way migrations should therefore keep `rollbackSchemaCompatible: false` and require a separately designed recovery procedure.

## Disclosure boundary

Assessment output and drain status contain only bounded release/replica identifiers, counts, booleans, and categorical state. They should not contain database connection strings, GitHub credentials, webhook secrets, repository contents, scanner output, or backend exception text.

These controls are operational evidence, not assertions that GitHub accepted credentials, that every request is authorized, that a scanner sandbox is correct, or that a deployment platform actually performed the requested rollout steps.
