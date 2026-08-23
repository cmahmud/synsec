# GitHub App shared-state deployment contract

SynSec's built-in GitHub App replay store, installation state, and scan queue are designed for a single hosted runtime using local durable state. They must not be treated as transactional multi-host infrastructure merely because the state directory is placed on NFS, a shared volume, or another network filesystem.

`validateGitHubAppDeployment()` makes that boundary machine-checkable. `replicaCount` defaults to `1`. A deployment declaring more than one replica fails readiness unless it also declares a `shared-transactional` state backend with every coordination guarantee SynSec's hosted runtime depends on.

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

The canonical capability names are exported as `REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES`. Backend/provisioning integrations should use that list rather than maintaining a duplicate copy.

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

## Versioned backend evidence contract

Capability booleans are useful for deployment preflight, but they are intentionally not enough to identify or review a concrete backend implementation. `@synsec/github/shared-state-contract` therefore exports a separate versioned, secret-free backend contract:

```ts
{
  contractVersion: 1,
  backendId: "postgres-v1",
  implementationVersion: "0.2.0",
  capabilities: {
    atomicReplayClaim: true,
    atomicQueueInsertion: true,
    atomicQueueClaimWithFence: true,
    compareAndSetLeaseRenewal: true,
    fencedQueueTransitions: true,
    transactionalInstallationState: true,
    sharedAuthorizationState: true
  },
  evidence: [
    {
      capability: "atomicReplayClaim",
      mechanism: "database-constraint",
      reference: "conformance-atomicReplayClaim"
    }
  ]
}
```

A valid contract must include exactly one bounded evidence record for every required capability. Evidence mechanisms are restricted to known coordination primitives such as database constraints, serializable transactions, compare-and-set operations, fencing tokens, and shared durable stores. References are bounded non-secret identifiers; arbitrary URLs, connection strings, credentials, control characters, and unknown fields are rejected.

Use `assessGitHubAppSharedStateBackendContract()` to obtain deterministic readiness diagnostics, or `assertGitHubAppSharedStateBackendContract()` at an adapter integration boundary. `GITHUB_APP_SHARED_STATE_CONTRACT_VERSION` is currently `1`.

This contract is still **not certification**. It binds a concrete adapter/version to reviewable implementation evidence so that future database adapters and their concurrency tests have a stable interface. SynSec does not infer that a backend is safe merely because it can produce this document.

## Actionable readiness diagnostics

Provisioning and deployment tooling can evaluate a capability declaration directly without parsing human-readable error messages:

```ts
const assessment = assessGitHubAppSharedStateCapabilities(capabilities);
if (!assessment.complete) {
  console.error("Missing shared-state guarantees:", assessment.missing);
}
```

`assessment.missing` is emitted in stable contract order and contains only capability identifiers. When deployment validation emits `shared-state-capabilities-incomplete`, the corresponding issue also carries the same identifiers in `missingCapabilities`. This output is safe for startup diagnostics because it contains no database connection strings, credentials, filesystem contents, or backend-provided free-form text.

Operators can run the same check offline from the setup CLI. The input file contains capability booleans only; connection strings, credentials, and unknown fields are rejected.

```json
{
  "atomicReplayClaim": true,
  "atomicQueueInsertion": true,
  "atomicQueueClaimWithFence": true,
  "compareAndSetLeaseRenewal": true,
  "fencedQueueTransitions": true,
  "transactionalInstallationState": true,
  "sharedAuthorizationState": true
}
```

```sh
synsec-github-app shared-state capabilities.json --json
```

The command exits `0` only when every required guarantee is declared `true`. Missing or false guarantees exit `2` and are returned by name. Invalid schema or unsupported fields exit `1` without echoing supplied values.

Treat these diagnostics as requirements to satisfy, not as proof that a backend really implements the declared guarantees. A production adapter still needs tests against its actual database concurrency semantics.

## Fail-closed behavior

For `replicaCount > 1`:

- an omitted backend or `kind: "filesystem"` produces `shared-state-required`;
- a `shared-transactional` backend missing any required guarantee produces `shared-state-capabilities-incomplete` plus the exact `missingCapabilities` identifiers;
- invalid replica counts produce `invalid-replica-count` before shared-state evaluation;
- `createLocalGitHubAppRuntime()` rejects the configuration regardless of a declared backend because that factory always instantiates the filesystem stores.

A single replica retains the current filesystem behavior. This keeps local and single-host deployments compatible while preventing configuration from overstating horizontal-scaling safety.

## What a future backend adapter must preserve

A real shared backend should expose operations matching SynSec's existing security invariants rather than generic key/value reads and writes. In particular, queue completion and publication ownership must remain fence-bound, webhook replay claims must remain unique and retry-safe, and installation authorization must be checked from shared durable state at execution time.

Before a shared backend is accepted for horizontal production use, its integration test suite should exercise concurrent duplicate replay claims, duplicate queue inserts, competing claimers, stale-fence renew/release/complete attempts, installation authorization changes racing worker execution, and restart/reconnect behavior. Passing the declaration preflight or versioned evidence contract alone is not certification.

Do not weaken those invariants to fit a storage product. If a backend cannot provide the required atomicity, keep SynSec at one application replica.
