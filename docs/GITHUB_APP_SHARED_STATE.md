# GitHub App shared-state deployment contract

SynSec's built-in GitHub App replay store, installation state, and scan queue are designed for a single hosted runtime using local durable state. They must not be treated as transactional multi-host infrastructure merely because the state directory is placed on NFS, a shared volume, or another network filesystem.

`validateGitHubAppDeployment()` now makes that boundary machine-checkable. `replicaCount` defaults to `1`. A deployment declaring more than one replica fails readiness unless it also declares a `shared-transactional` state backend with every coordination guarantee SynSec's hosted runtime depends on.

The concrete `createLocalGitHubAppRuntime()` factory adds a second guard at the implementation boundary. Its filesystem-backed runtime accepts an omitted `replicaCount` or exactly `1`; any other declared cardinality is rejected before runtime state directories are created. This prevents callers that bypass deployment preflight from representing the local runtime as horizontally safe.

## Required guarantees

A multi-replica backend must provide all of the following as backend-level atomic operations:

- **Atomic webhook replay claim.** Two intake replicas cannot both accept the same delivery claim.
- **Atomic queue insertion.** Idempotent work insertion cannot create duplicate jobs under concurrent dispatch.
- **Atomic queue claim with a fresh fence.** Claiming work and establishing its fencing identity are one indivisible transition.
- **Compare-and-set lease renewal.** Only the currently fenced worker can extend its lease.
- **Fenced queue transitions.** Retry release, failure, completion, and other terminal transitions reject stale workers.
- **Transactional installation state.** Installation/repository-selection mutations cannot expose partial authorization state.
- **Shared authorization state.** Every intake and worker replica observes the same durable authorization authority.

These are correctness and authorization requirements, not performance hints. Losing any one of them can turn a stale worker, concurrent webhook, or repository-selection race into duplicate publication or work performed after authorization changed.

## Deployment example

```ts
validateGitHubAppDeployment({
  // existing App, listener, path, credential, and isolation configuration...
  replicaCount: 3,
  stateBackend: {
    kind: "shared-transactional",
    capabilities: {
      atomicReplayClaim: true,
      atomicQueueInsertion: true,
      atomicQueueClaimWithFence: true,
      compareAndSetLeaseRenewal: true,
      fencedQueueTransitions: true,
      transactionalInstallationState: true,
      sharedAuthorizationState: true,
    },
  },
});
```

The declaration is an integration contract. It does **not** implement those guarantees, certify an arbitrary database, or convert the built-in filesystem stores into a shared backend. Production operators must map each capability to a real database transaction, unique constraint, compare-and-set statement, or equivalent strongly consistent primitive in the selected backend.

## Fail-closed behavior

For `replicaCount > 1`:

- an omitted backend or `kind: "filesystem"` produces `shared-state-required`;
- a `shared-transactional` backend missing any required guarantee produces `shared-state-capabilities-incomplete`;
- invalid replica counts produce `invalid-replica-count` before shared-state evaluation;
- `createLocalGitHubAppRuntime()` rejects the configuration regardless of a declared backend because that factory always instantiates the filesystem stores.

A single replica retains the current filesystem behavior. This keeps local and single-host deployments compatible while preventing configuration from overstating horizontal-scaling safety.

## What a future backend adapter must preserve

A real shared backend should expose operations matching SynSec's existing security invariants rather than generic key/value reads and writes. In particular, queue completion and publication ownership must remain fence-bound, webhook replay claims must remain unique and retry-safe, and installation authorization must be checked from shared durable state at execution time.

Do not weaken those invariants to fit a storage product. If a backend cannot provide the required atomicity, keep SynSec at one application replica.
