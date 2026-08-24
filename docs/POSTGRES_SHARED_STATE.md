# PostgreSQL shared state

SynSec now includes a built-in PostgreSQL implementation for all seven hosted GitHub App shared-state capabilities. The low-level replay/queue pieces are exported from `@synsec/github/postgres-shared-state`, transactional installation authorization from `@synsec/github/postgres-installation-store`, and the production composition boundary from `@synsec/github/postgres-shared-backend`.

All database APIs accept a caller-owned PostgreSQL pool through a narrow `query()` / `connect()` interface. SynSec does not accept, parse, persist, or expose a database connection string through these APIs. Hosting code remains responsible for constructing the client from its secret manager and for keeping database credentials outside scanner processes.

## Implemented guarantees

The PostgreSQL backend implements and exercises the complete shared-state contract against a real PostgreSQL 16 service in CI:

- `atomicReplayClaim` — one SQL upsert/CTE atomically accepts a new or expired delivery while concurrent replicas observe the same durable claim.
- `atomicQueueInsertion` — a database unique constraint prevents duplicate delivery insertion; queue capacity and insertion are serialized by a transaction-scoped PostgreSQL advisory lock.
- `atomicQueueClaimWithFence` — workers select claimable work with `FOR UPDATE SKIP LOCKED` and create a fresh random lease id in the same atomic update.
- `compareAndSetLeaseRenewal` — renewal updates only the currently leased row with the exact unexpired lease id.
- `fencedQueueTransitions` — release, failure, and completion require the exact current unexpired lease id.
- `transactionalInstallationState` — installation and repository-selection read/modify/write operations execute on one transaction-scoped connection under an installation-specific PostgreSQL advisory lock, so independent replicas cannot overwrite one another's repository deltas.
- `sharedAuthorizationState` — authorization checks query the shared durable installation table each time, so suspension, deletion, and repository-selection changes become authoritative across independent replicas rather than relying on process-local caches.

The database schema stores only replay identity/timestamps, commit-pinned scan-job metadata, installation/account authorization metadata, selected repository identities, lease metadata, and schema version state. It does not store installation tokens, GitHub App private keys, webhook secrets, repository credentials, scanner output, source excerpts, or arbitrary outbound URLs.

## Canonical conformance

The PostgreSQL CI job runs SynSec's existing canonical seven-scenario conformance runner against the real database service. The matrix covers concurrent duplicate replay claims, concurrent idempotent queue insertion, competing fenced claims, stale-fence renewal, stale-fence terminal transitions, concurrent installation-selection mutation, and cross-replica authorization revocation.

Passing CI demonstrates the behavior of the built-in adapter implementation under those adversarial scenarios. It is still **evidence**, not a magic property inferred from a configuration flag. `createGitHubAppPostgresSharedRuntime()` routes through the same evidence gate as every other shared runtime and requires a complete conformance report whose `backendId` and `implementationVersion` exactly match the built-in PostgreSQL contract.

The current stable identity is:

- backend id: `postgres-v1`
- implementation version: `0.2.0-postgres-v1`

Do not edit these fields in a stored report to make stale evidence appear current. The evidence gate recomputes canonical coverage and checks exact identity matching.

## Schema migration

Use `migrateSynSecGitHubPostgresBackend(pool)` from `@synsec/github/postgres-shared-backend` before activating the stores. The composed migration:

- runs under one transaction-scoped PostgreSQL advisory lock so concurrent deployment replicas cannot race DDL;
- creates replay, queue, installation, index, and schema-version structures idempotently;
- records shared-state schema version `1` and fails closed on an unsupported recorded version; and
- repairs the pre-release replay timestamp shape to millisecond precision so the exact replay claim token returned through JavaScript can be used for compare-and-set release without precision loss.

Migration remains deliberately separate from runtime construction. Production operators can therefore execute it with a purpose-specific deployment identity and avoid granting DDL privileges to long-running webhook or worker processes.

## Store composition

```ts
import { Pool } from "pg";
import {
  buildSynSecGitHubPostgresBackendContract,
  createSynSecGitHubPostgresSharedStores,
  migrateSynSecGitHubPostgresBackend,
} from "@synsec/github/postgres-shared-backend";

const pool = new Pool({ connectionString: process.env.SYNSEC_DATABASE_URL });
await migrateSynSecGitHubPostgresBackend(pool);

const stores = createSynSecGitHubPostgresSharedStores(pool);
const contract = buildSynSecGitHubPostgresBackendContract();
```

The example keeps the connection string in hosting code. Do not pass `SYNSEC_DATABASE_URL`, GitHub tokens, App private keys, webhook secrets, or other hosting credentials into scanner environments.

## Evidence-gated hosted runtime

Once a complete portable conformance report has been produced for the exact built-in backend identity, hosting code can compose the concrete stores through `createGitHubAppPostgresSharedRuntime()`:

```ts
const runtime = createGitHubAppPostgresSharedRuntime({
  pool,
  conformanceReport,
  webhookSecret,
  worker,
});
```

The factory generates the backend contract itself and does not accept caller-supplied capability booleans. Invalid, incomplete, tampered, or stale conformance evidence fails before the external stores become active.

This runtime boundary does not manage PostgreSQL credentials, create cloud databases, run migrations automatically, or weaken SynSec's existing GitHub authorization, replay, lease-fencing, exact-commit acquisition, scanner credential-isolation, or publication checks.

## Operational boundary

A passing shared-state conformance report establishes only the tested coordination semantics. It does not certify PostgreSQL availability, backups, encryption, tenant isolation, disaster recovery, network policy, scanner sandboxing, or GitHub App credential management. Those remain separate hosting responsibilities and readiness boundaries.
