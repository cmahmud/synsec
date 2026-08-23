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

`@synsec/github/shared-state-conformance` exports `GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS`, a stable minimum adversarial scenario for each required shared-state capability. `assessGitHubAppSharedStateConformanceCoverage()` maps completed scenario IDs back to the exact missing scenarios and capabilities. Unknown or duplicate IDs cannot manufacture coverage.

The current required scenarios cover:

- concurrent duplicate webhook replay claims;
- concurrent idempotent queue insertion;
- competing queue claimers with fresh fencing identities;
- stale-fence lease renewal rejection;
- stale-fence retry/failure/completion rejection;
- transactional installation/repository-selection mutation;
- cross-replica authorization revocation visibility.

Adapters should record these stable scenario IDs only after the corresponding test has passed against the real backend. The coverage assessor does not execute a database or validate the truth of a claimed test result; it prevents drift in what SynSec considers the minimum concurrency test matrix.

Additional adapter tests should cover transaction rollback, reconnect/restart behavior, and durable visibility across independent application processes. Those operational tests remain backend-specific and should not be replaced by mocks.

The versioned contract, composition seam, and conformance registry make tests attributable to a concrete adapter build. They are not a substitute for the tests themselves, and none of these APIs makes the built-in filesystem stores horizontally safe.
