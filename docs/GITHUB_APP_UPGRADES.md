# GitHub App rolling upgrades and rollback

SynSec's hosted GitHub App has durable shared state and fenced workers, but those properties do not by themselves make an application rollout safe. A production service manager also needs exact fleet membership, fresh runtime observations, drained work, an immutable previous artifact, and an explicit database-schema rollback decision.

`@synsec/github/app-upgrade` provides a secret-free gate for that orchestration boundary. `@synsec/github/app-drain` provides the local enforced webhook-admission primitive used while draining one replica. Neither module restarts processes, mutates PostgreSQL, executes migrations, revokes credentials, or calls a deployment platform.

## Trusted observations

The service manager supplies:

- distinct current and target release identifiers;
- current and target shared-state schema versions;
- the exact expected replica identifiers;
- one fresh observation for every replica containing the loaded release, schema version, readiness, active lease count, and observation timestamp;
- whether the immutable previous release artifact is still deployable; and
- whether a schema change is explicitly rollback-compatible.

Replica observations and `assessedAt` must come from trusted supervisor/runtime state. Repository content, webhook payloads, scanner output, or user-controlled metadata must never be allowed to manufacture these values.

## Enforced local admission drain

Wrap the production webhook handler with `createSynSecGitHubAppDrainController()` before passing it to the GitHub App listener. `beginDrain()` immediately prevents new webhook requests from entering the wrapped handler. Rejected requests receive only an aggregate `503 {"status":"draining"}` response plus `Retry-After: 1`, allowing GitHub to retry without reflecting delivery ids, repositories, payloads, or backend errors.

Requests admitted before the drain continue running. `waitForDrained()` waits only for those in-process webhook calls; it does not claim that background scan workers or durable queue leases are drained. The service manager must separately observe the worker lease count before replacing the replica. `resumeAdmission()` is explicit so a failed rollout can reopen the old replica without recreating the handler.

## Start gate

`readyToBeginRollout` is true only when the exact expected fleet is:

- still on the previous release;
- ready;
- drained (`activeLeases === 0`);
- represented by fresh observations; and
- rollback-capable.

For schema-changing releases, rollback capability must be an explicit operator/migration property. SynSec does not infer reversibility merely because a migration completed successfully.

A conservative rolling sequence is:

1. call `beginDrain()` on the replica being replaced;
2. wait for `waitForDrained()` so no admitted webhook handler is still executing;
3. stop worker intake and observe its fenced durable lease count reach zero;
4. keep the previous immutable artifact and compatible database state available;
5. replace that replica with the target release;
6. verify its normal readiness and shared-state health;
7. continue one replica at a time; and
8. run the final fleet assessment before retiring the previous artifact.

The assessment intentionally treats active durable work as a rollout blocker. A deployment platform can choose a different drain policy, but it must not reinterpret this result as proof that interrupting workers is safe.

## Finalization gate

`readyToFinalizeRollout` requires the exact expected fleet to be fresh, ready, drained, on the target release, and reporting the target schema version. Old-release replicas or target replicas reporting another schema prevent finalization.

Only after finalization should an operator consider removing the previous application artifact. Credential rotation is separate: follow `GITHUB_APP_CREDENTIAL_RELOAD.md` and `GITHUB_APP_CREDENTIAL_RELOAD_FRESHNESS.md` before retiring an old GitHub credential.

## Rollback

`rollbackAllowed` requires the previous immutable application artifact to remain available. If the release changes the database schema, the caller must additionally assert that the target schema is compatible with the previous application release.

This is deliberately conservative. A migration declaration, application readiness probe, or successful target startup is not evidence that an old binary can safely use the new schema. Destructive or one-way migrations should therefore keep `rollbackSchemaCompatible: false` and require a separately designed recovery procedure.

## Disclosure boundary

Assessment output and drain status contain only bounded release/replica identifiers, counts, booleans, and categorical state. They should not contain database connection strings, GitHub credentials, webhook secrets, repository contents, scanner output, or backend exception text.

These controls are operational evidence, not assertions that GitHub accepted credentials, that every request is authorized, that a scanner sandbox is correct, or that a deployment platform actually performed the requested rollout steps.
