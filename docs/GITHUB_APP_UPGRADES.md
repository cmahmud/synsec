# GitHub App rolling upgrades and rollback

SynSec's hosted GitHub App has durable shared state and fenced workers, but those properties do not by themselves make an application rollout safe. A production service manager also needs exact fleet membership, fresh runtime observations, drained work, an immutable previous artifact, and an explicit database-schema rollback decision.

`@synsec/github/app-upgrade` provides a secret-free gate for that orchestration boundary. It does **not** restart processes, mutate PostgreSQL, execute migrations, revoke credentials, or call a deployment platform.

## Trusted observations

The service manager supplies:

- distinct current and target release identifiers;
- current and target shared-state schema versions;
- the exact expected replica identifiers;
- one fresh observation for every replica containing the loaded release, schema version, readiness, active lease count, and observation timestamp;
- whether the immutable previous release artifact is still deployable; and
- whether a schema change is explicitly rollback-compatible.

Replica observations and `assessedAt` must come from trusted supervisor/runtime state. Repository content, webhook payloads, scanner output, or user-controlled metadata must never be allowed to manufacture these values.

## Start gate

`readyToBeginRollout` is true only when the exact expected fleet is:

- still on the previous release;
- ready;
- drained (`activeLeases === 0`);
- represented by fresh observations; and
- rollback-capable.

For schema-changing releases, rollback capability must be an explicit operator/migration property. SynSec does not infer reversibility merely because a migration completed successfully.

A useful rolling sequence is:

1. stop admitting new scan work to the replica being replaced;
2. wait for its fenced work/lease count to reach zero;
3. keep the previous immutable artifact and compatible database state available;
4. replace one replica with the target release;
5. verify that replica's normal readiness and shared-state health;
6. continue one replica at a time; and
7. run the final fleet assessment before retiring the previous artifact.

The assessment intentionally treats active work as a rollout blocker. A deployment platform can choose a different drain policy, but it must not reinterpret this result as proof that interrupting workers is safe.

## Finalization gate

`readyToFinalizeRollout` requires the exact expected fleet to be fresh, ready, drained, on the target release, and reporting the target schema version. Old-release replicas or target replicas reporting another schema prevent finalization.

Only after finalization should an operator consider removing the previous application artifact. Credential rotation is separate: follow `GITHUB_APP_CREDENTIAL_RELOAD.md` and `GITHUB_APP_CREDENTIAL_RELOAD_FRESHNESS.md` before retiring an old GitHub credential.

## Rollback

`rollbackAllowed` requires the previous immutable application artifact to remain available. If the release changes the database schema, the caller must additionally assert that the target schema is compatible with the previous application release.

This is deliberately conservative. A migration declaration, application readiness probe, or successful target startup is not evidence that an old binary can safely use the new schema. Destructive or one-way migrations should therefore keep `rollbackSchemaCompatible: false` and require a separately designed recovery procedure.

## Disclosure boundary

Assessment output contains only bounded release/replica identifiers, counts, booleans, and categorical issue codes. It should not contain database connection strings, GitHub credentials, webhook secrets, repository contents, scanner output, or backend exception text.

The gate is operational evidence, not an assertion that GitHub accepted credentials, that every request is authorized, that a scanner sandbox is correct, or that a deployment platform actually performed the requested rollout steps.
