import type { GitHubAppSharedStateBackendContract } from "./shared-state-contract.js";
import {
  migrateSynSecGitHubPostgresState,
  PostgresGitHubScanQueue,
  PostgresGitHubWebhookReplayStore,
  type PostgresGitHubSharedStateOptions,
  type PostgresPoolLike,
} from "./postgres-shared-state.js";
import {
  migrateSynSecGitHubPostgresInstallationState,
  PostgresGitHubInstallationStore,
} from "./postgres-installation-store.js";

export const SYNSEC_GITHUB_POSTGRES_BACKEND_ID = "postgres-v1" as const;
export const SYNSEC_GITHUB_POSTGRES_IMPLEMENTATION_VERSION = "0.2.0-postgres-v1" as const;

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
 * Apply all PostgreSQL shared-state schema changes required by the built-in adapter.
 *
 * The timestamp ALTER is intentionally idempotent and repairs databases created by an earlier
 * pre-release adapter build whose replay claim column retained sub-millisecond precision. Keeping
 * this repair explicit preserves exact claim-token compare-and-set semantics across upgrades.
 */
export async function migrateSynSecGitHubPostgresBackend(pool: PostgresPoolLike): Promise<void> {
  await migrateSynSecGitHubPostgresState(pool);
  await pool.query(
    `ALTER TABLE synsec_github_replay
     ALTER COLUMN received_at TYPE timestamptz(3)
     USING date_trunc('milliseconds', received_at)`,
  );
  await migrateSynSecGitHubPostgresInstallationState(pool);
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
