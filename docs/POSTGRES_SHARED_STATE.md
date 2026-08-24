# PostgreSQL shared state

SynSec now includes a PostgreSQL implementation for the webhook replay and scan-queue portions of the hosted GitHub App shared-state contract.

The implementation is exported from `@synsec/github/postgres-shared-state` and accepts a caller-owned PostgreSQL pool through a narrow `query()` / `connect()` interface. SynSec does not accept, parse, persist, or expose a database connection string through this API. Hosting code remains responsible for creating the database client from its secret manager and for keeping database credentials outside scanner processes.

## Implemented guarantees

The PostgreSQL adapter currently implements and continuously exercises these shared-state capabilities against a real PostgreSQL service in CI:

- `atomicReplayClaim` — one SQL upsert/CTE atomically accepts a new or expired delivery while concurrent replicas observe the same durable claim.
- `atomicQueueInsertion` — a database unique constraint prevents duplicate delivery insertion; queue capacity and insertion are serialized by a transaction-scoped PostgreSQL advisory lock.
- `atomicQueueClaimWithFence` — workers select claimable work with `FOR UPDATE SKIP LOCKED` and create a fresh random lease id in the same atomic update.
- `compareAndSetLeaseRenewal` — renewal updates only the currently leased row with the exact unexpired lease id.
- `fencedQueueTransitions` — release, failure, and completion require the exact current unexpired lease id.

The schema stores commit-pinned job metadata and installation ids only. It does not contain installation tokens, GitHub App private keys, webhook secrets, repository credentials, scanner output, source excerpts, or arbitrary outbound URLs.

## Not implemented yet

This module does **not** yet satisfy the complete seven-capability SynSec shared-state contract. In particular:

- `transactionalInstallationState` is still missing from the PostgreSQL adapter/runtime path. The current installation synchronization helper performs a read-modify-write sequence protected by an in-process lock; merely replacing its filesystem `get()` / `put()` methods with database queries would not make repository-selection deltas safe across replicas.
- `sharedAuthorizationState` therefore also remains incomplete as a demonstrated multi-host runtime guarantee.

For that reason, the PostgreSQL replay/queue adapter must not be represented as a complete backend contract and cannot by itself pass `createGitHubAppSharedRuntime()` production evidence checks.

## Schema migration

Call `migrateSynSecGitHubPostgresState(pool)` before activating the adapter. Migration runs in one database transaction, creates the required tables/indexes idempotently, and records schema version `1` in `synsec_github_schema`. A different recorded version fails closed rather than being silently overwritten.

Migration is intentionally separate from runtime construction so operators can run it with a purpose-specific deployment identity rather than granting DDL privileges to long-running webhook or worker processes.

## Example integration

```ts
import { Pool } from "pg";
import {
  migrateSynSecGitHubPostgresState,
  PostgresGitHubScanQueue,
  PostgresGitHubWebhookReplayStore,
} from "@synsec/github/postgres-shared-state";

const pool = new Pool({ connectionString: process.env.SYNSEC_DATABASE_URL });
await migrateSynSecGitHubPostgresState(pool);

const replayStore = new PostgresGitHubWebhookReplayStore(pool);
const queue = new PostgresGitHubScanQueue(pool);
```

The example keeps the connection string in hosting code. Do not pass `SYNSEC_DATABASE_URL`, GitHub tokens, App private keys, webhook secrets, or other hosting credentials into scanner environments.

## Real-backend verification

The repository CI starts PostgreSQL 16 and verifies migration idempotence, competing replay claims, concurrent idempotent queue insertion, competing queue claims, lease reclamation, fresh fencing identities, and stale-fence renewal rejection. Those tests demonstrate only the implemented replay/queue capabilities. Complete multi-replica readiness still requires transactional installation/authorization storage and then the canonical seven-scenario shared-state conformance report bound to the exact adapter version.
