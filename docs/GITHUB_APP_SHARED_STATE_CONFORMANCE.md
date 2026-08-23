# GitHub App shared-state conformance runner

SynSec's shared-state capability declaration and versioned backend contract describe what a horizontally scaled backend must guarantee. They do not prove that a database adapter actually preserves those guarantees under concurrency.

`@synsec/github/shared-state-conformance-runner` provides the executable boundary for that proof. Adapter authors supply one callback for every canonical adversarial scenario and a `reset()` hook that isolates scenario state. SynSec executes the matrix in stable order, bounds each scenario by a timeout, and produces a schema-versioned result containing only scenario ids, status, duration, and capability coverage.

## Adapter shape

```ts
import {
  runGitHubAppSharedStateConformance,
} from "@synsec/github/shared-state-conformance-runner";

const report = await runGitHubAppSharedStateConformance({
  async reset() {
    await testDatabase.resetFixtures();
  },
  scenarios: {
    "replay.concurrent-duplicate-claim": async () => {
      // Race independent adapter clients against one delivery id and assert <= 1 accepted claim.
    },
    "queue.concurrent-idempotent-insert": async () => {
      // Race idempotent inserts and assert one durable logical job identity.
    },
    "queue.concurrent-claim-fence": async () => {
      // Race workers and assert one current lease plus a fresh fence per successful claim.
    },
    "queue.stale-fence-renewal": async () => {
      // Supersede a lease, then assert the stale fence cannot renew it.
    },
    "queue.stale-fence-terminal-transitions": async () => {
      // Assert a stale fence cannot release, fail, or complete newer work.
    },
    "installation.concurrent-selection-mutation": async () => {
      // Race installation/repository-selection mutations and reject partial authorization state.
    },
    "authorization.cross-replica-revocation": async () => {
      // Revoke authorization through one client and prove independent replicas fail closed.
    },
  },
});

if (!report.complete) process.exitCode = 1;
```

The runner requires exactly the canonical scenario ids. Missing callbacks and invented extra ids are rejected before execution, preventing a test harness from manufacturing coverage by renaming or omitting required cases.

## Fail-closed execution

Scenarios run sequentially so failures are attributable and adapter-owned fixtures can be reset between adversarial cases. `reset()` runs before every scenario. A reset failure fails that scenario and the runner continues with the remaining matrix.

The default per-scenario timeout is 15 seconds. Adapter suites may select an integer from 100 ms through 120 seconds. A timeout is a failed conformance result; a hung database operation cannot count as evidence.

The report deliberately excludes thrown error text. Database exceptions frequently contain hostnames, SQL, connection strings, credentials, or tenant data. Adapter CI may retain its own separately sanitized diagnostics, but SynSec's portable conformance artifact only records bounded structural results.

## What a pass means

A complete report means every canonical callback completed successfully within its bound. It does **not** certify a storage product by itself. Production evidence should bind all of the following to the same tested revision:

- exact adapter implementation version;
- exact backend/database version and relevant isolation configuration;
- the versioned `shared-state-contract` evidence document;
- the schema-versioned conformance report;
- CI provenance showing the scenarios ran against a real database, preferably with independent connections/processes where the invariant requires cross-replica behavior.

Do not replace the adversarial operations with mocks of the adapter itself. The purpose of this runner is to make real-backend concurrency tests uniform and reviewable while keeping credentials and backend-specific internals outside SynSec's reports.

## Relationship to deployment readiness

`validateGitHubAppDeployment()` still fails multi-replica configurations closed unless every required capability is declared. The conformance runner adds evidence; it does not bypass deployment validation, automatically enable horizontal scaling, or turn the built-in filesystem stores into distributed infrastructure.

A production shared-state adapter remains responsible for implementing atomic replay claims, idempotent queue insertion, fenced ownership and terminal transitions, compare-and-set lease renewal, transactional installation state, and shared durable authorization using primitives provided by the selected backend.
