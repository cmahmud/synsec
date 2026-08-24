import type { GitHubAppSharedStateBackendContract } from "./shared-state-contract.js";
import {
  PostgresGitHubScanQueue,
  PostgresGitHubWebhookReplayStore,
  SYNSEC_GITHUB_POSTGRES_MIGRATIONS,
  SYNSEC_GITHUB_POSTGRES_SCHEMA_VERSION,
  type PostgresGitHubSharedStateOptions,
  type PostgresPoolLike,
} from "./postgres-shared-state.js";
import {
  PostgresGitHubInstallationStore,
  SYNSEC_GITHUB_POSTGRES_INSTALLATION_MIGRATIONS,
} from "./postgres-installation-store.js";

export const SYNSEC_GITHUB_POSTGRES_BACKEND_ID = "postgres-v1" as const;
export const SYNSEC_GITHUB_POSTGRES_IMPLEMENTATION_VERSION = "0.2.0-postgres-v1" as const;
const POSTGRES_MIGRATION_LOCK = "synsec-github-postgres-shared-state-v1";

/**
 * Secret-free declaration for the concrete built-in PostgreSQL adapter implementation.
 *
 * This declaration is not sufficient for production activation by itself. The shared runtime still
 * requires a complete canonical conformance report bound to this exact backend id/version.
 */
export function buildSynSecGitHubPostgresBackendContract(): GitHubAppSharedStateBackendContract {
  return {
    contractVersion: 1,
    backendId: SYNSEC_GITHUB_POSTGRES_BACKEND_ID,
    implementationVersion: SYNSEC_GITHUB_POSTGRES_IMPLEMENTATION_VERSION,
    capabilities: {
      atomicReplayClaim: true,
      atomicQueueInsertion: true,
      atomicQueueClaimWithFence: true,
      compareAndSetLeaseRenewal: true,
      fencedQueueTransitions: true,
      transactionalInstallationState: true,
      sharedAuthorizationState: true,
    },
    evidence: [
      {
        capability: "atomicReplayClaim",
        mechanism: "database-constraint",
        reference: "postgres-shared-state.replay-concurrent-claim",
      },
      {
        capability: "atomicQueueInsertion",
        mechanism: "database-constraint",
        reference: "postgres-shared-state.queue-unique-delivery",
      },
      {
        capability: "atomicQueueClaimWithFence",
        mechanism: "fencing-token",
        reference: "postgres-shared-state.queue-skip-locked-fence",
      },
      {
        capability: "compareAndSetLeaseRenewal",
        mechanism: "compare-and-set",
        reference: "postgres-shared-state.queue-lease-renewal-cas",
      },
      {
        capability: "fencedQueueTransitions",
        mechanism: "fencing-token",
        reference: "postgres-shared-state.queue-terminal-fences",
      },
      {
        capability: "transactionalInstallationState",
        mechanism: "serializable-transaction",
        reference: "postgres-installation-state.transaction-lock",
      },
      {
        capability: "sharedAuthorizationState",
        mechanism: "shared-durable-store",
        reference: "postgres-installation-state.shared-authorization",
      },
    ],
  };
}

/**
 * Apply the complete PostgreSQL shared-state schema under one transaction-scoped advisory lock.
 * Concurrent replicas invoking this helper therefore cannot race PostgreSQL DDL creation.
 *
 * The timestamp ALTER is intentionally idempotent and repairs databases created by an earlier
 * pre-release adapter build whose replay claim column retained sub-millisecond precision. Keeping
 * this repair explicit preserves exact claim-token compare-and-set semantics across upgrades.
 */
export async function migrateSynSecGitHubPostgresBackend(pool: PostgresPoolLike): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [POSTGRES_MIGRATION_LOCK]);
    for (const statement of SYNSEC_GITHUB_POSTGRES_MIGRATIONS) await client.query(statement);
    await client.query(
      `ALTER TABLE synsec_github_replay
       ALTER COLUMN received_at TYPE timestamptz(3)
       USING date_trunc('milliseconds', received_at)`,
    );
    for (const statement of SYNSEC_GITHUB_POSTGRES_INSTALLATION_MIGRATIONS) await client.query(statement);

    const current = await client.query(
      "SELECT version FROM synsec_github_schema WHERE component = $1 FOR UPDATE",
      ["shared-state"],
    );
    if (current.rows.length > 1) throw new Error("SynSec PostgreSQL schema metadata is inconsistent.");
    if (current.rows.length === 1) {
      const version = Number(current.rows[0]?.version);
      if (version !== SYNSEC_GITHUB_POSTGRES_SCHEMA_VERSION) {
        throw new Error("SynSec PostgreSQL shared-state schema version is unsupported.");
      }
    } else {
      await client.query(
        "INSERT INTO synsec_github_schema(component, version) VALUES ($1, $2)",
        ["shared-state", SYNSEC_GITHUB_POSTGRES_SCHEMA_VERSION],
      );
    }
    await client.query("COMMIT");
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {
      // Preserve the migration failure; rollback diagnostics may contain backend connection details.
    }
    throw error;
  } finally {
    client.release();
  }
}

export interface SynSecGitHubPostgresSharedStores {
  replayStore: PostgresGitHubWebhookReplayStore;
  installationStore: PostgresGitHubInstallationStore;
  queue: PostgresGitHubScanQueue;
}

/**
 * Construct the three shared stores from a caller-owned pool after migrations have been applied.
 * Database credentials remain entirely in hosting code; this factory accepts only an established
 * query/connect capability and never serializes backend connection details.
 */
export function createSynSecGitHubPostgresSharedStores(
  pool: PostgresPoolLike,
  options: PostgresGitHubSharedStateOptions = {},
): SynSecGitHubPostgresSharedStores {
  return {
    replayStore: new PostgresGitHubWebhookReplayStore(pool, options),
    installationStore: new PostgresGitHubInstallationStore(pool),
    queue: new PostgresGitHubScanQueue(pool, options),
  };
}
