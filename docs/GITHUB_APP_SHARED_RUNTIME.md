# GitHub App shared runtime integration seam

`createGitHubAppSharedRuntime()` is the integration boundary for future transactional GitHub App state adapters. It composes externally implemented replay, installation-authorization, and scan-queue stores into the same repository-first webhook and worker pipeline used by SynSec's hosted runtime.

This API does **not** ship a database adapter and does not certify supplied stores. Before composition it requires a complete versioned `GitHubAppSharedStateBackendContract`, including one bounded implementation-evidence record for every required coordination capability. The backend itself must still satisfy those guarantees under real concurrent database execution.

## Why this seam exists

The built-in `createLocalGitHubAppRuntime()` deliberately constructs filesystem stores and rejects application replica counts other than one. Replacing its directory with NFS or a shared volume does not provide transactional coordination.

A real horizontally scalable deployment needs different persistence implementations while preserving SynSec's existing security boundaries. The shared runtime accepts those implementations structurally rather than weakening the local runtime or adding database credentials to SynSec's core configuration.

```ts
const runtime = createGitHubAppSharedRuntime({
  backendContract,
  webhookSecret,
  replayStore,
  installationStore,
  queue,
  worker: {
    config,
    getInstallationToken,
    publishSarif: true,
  },
});
```

The supplied stores must implement the existing narrow interfaces used by webhook intake and workers. In particular, the queue must provide fresh fencing identities on claim, compare-and-set lease renewal when supported, and fence-bound release/failure/completion behavior. Installation authorization must come from shared durable state, and replay claims must remain globally unique and retry-safe.

## Credential boundary

The shared runtime does not accept a database URL, password, TLS key, or arbitrary backend options. Database clients and credentials remain inside the adapter implementation. The backend contract accepts only bounded adapter/version identifiers and bounded non-secret evidence references.

GitHub App credentials remain transport-only as elsewhere in SynSec. Scanner processes must never receive installation tokens, App private keys, webhook secrets, or database credentials.

## Required conformance work before production scaling

An adapter should not be treated as production-ready until integration tests run against its actual database and exercise at least:

- concurrent duplicate webhook replay claims;
- concurrent idempotent queue insertion;
- competing queue claimers receiving at most one active lease;
- stale-fence lease renewal, retry, failure, and completion attempts;
- authorization removal racing an already queued or leased job;
- transaction rollback and reconnect/restart behavior;
- durable visibility across independent application processes.

The versioned contract and composition seam make those tests attributable to a concrete adapter build. They are not a substitute for the tests themselves.
