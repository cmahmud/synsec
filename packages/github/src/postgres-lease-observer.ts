import type { PostgresPoolLike } from "./postgres-shared-state.js";

const MAX_ACTIVE_LEASES = 1_000_000;

/**
 * Count currently valid fenced scan-job leases from the transactional PostgreSQL backend.
 *
 * This is intended for trusted service-manager and rolling-upgrade orchestration. It queries durable
 * shared state directly and does not derive fleet drainage from in-process worker counters. Expired
 * leases are excluded because they are reclaimable and no longer establish current ownership.
 */
export async function countSynSecGitHubPostgresActiveLeases(pool: PostgresPoolLike): Promise<number> {
  if (!pool || typeof pool.query !== "function") {
    throw new Error("PostgreSQL shared-state pool is required for active-lease observation.");
  }
  const result = await pool.query(
    `SELECT count(*)::integer AS count
     FROM synsec_github_scan_jobs
     WHERE status = 'leased' AND lease_until > clock_timestamp()`,
  );
  if (result.rows.length !== 1) {
    throw new Error("PostgreSQL active-lease observation returned an invalid result shape.");
  }
  const raw = result.rows[0]?.count;
  const count = typeof raw === "number" ? raw : Number(raw);
  if (!Number.isSafeInteger(count) || count < 0 || count > MAX_ACTIVE_LEASES) {
    throw new Error("PostgreSQL active-lease observation returned an invalid count.");
  }
  return count;
}
