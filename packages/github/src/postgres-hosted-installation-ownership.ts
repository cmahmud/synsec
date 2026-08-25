import type {
  SynSecHostedInstallationOwnershipClaim,
  SynSecHostedInstallationOwnershipStore,
  SynSecHostedInstallationClaimResult,
} from "./hosted-installation-ownership.js";
import type { PostgresPoolLike, PostgresTransactionClient } from "./postgres-shared-state.js";

const MAX_TENANT_ID_LENGTH = 128;
const MAX_LOGIN_LENGTH = 255;

export const SYNSEC_GITHUB_POSTGRES_HOSTED_OWNERSHIP_MIGRATIONS = [
  `CREATE TABLE IF NOT EXISTS synsec_github_hosted_installation_ownership (
    installation_id bigint PRIMARY KEY CHECK (installation_id > 0),
    tenant_id varchar(128) NOT NULL,
    github_user_id bigint NOT NULL CHECK (github_user_id > 0),
    account_id bigint NOT NULL CHECK (account_id > 0),
    account_login varchar(255) NOT NULL,
    account_type varchar(16) NOT NULL CHECK (account_type IN ('User', 'Organization')),
    claimed_at timestamptz(3) NOT NULL DEFAULT date_trunc('milliseconds', clock_timestamp()),
    CHECK (tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$')
  )`,
  `CREATE INDEX IF NOT EXISTS synsec_github_hosted_installation_ownership_tenant_idx
    ON synsec_github_hosted_installation_ownership (tenant_id, installation_id)`,
] as const;

function positiveInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer.`);
  }
  return value;
}

function tenantId(value: unknown): string {
  if (typeof value !== "string") throw new Error("Hosted tenant id must be a string.");
  const normalized = value.trim();
  if (!normalized || normalized.length > MAX_TENANT_ID_LENGTH || !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(normalized)) {
    throw new Error("Hosted tenant id must be a bounded non-secret identifier.");
  }
  return normalized;
}

function accountLogin(value: unknown): string {
  if (typeof value !== "string") throw new Error("GitHub account login must be a string.");
  const normalized = value.trim();
  if (!normalized || normalized.length > MAX_LOGIN_LENGTH || /[\u0000-\u001f\u007f]/.test(normalized)) {
    throw new Error("GitHub account login is invalid.");
  }
  return normalized;
}

function validateClaim(input: SynSecHostedInstallationOwnershipClaim): SynSecHostedInstallationOwnershipClaim {
  const accountType = input?.accountType;
  if (accountType !== "User" && accountType !== "Organization") throw new Error("GitHub installation account type is invalid.");
  return {
    tenantId: tenantId(input?.tenantId),
    installationId: positiveInteger(input?.installationId, "GitHub installation id"),
    githubUserId: positiveInteger(input?.githubUserId, "Authenticated GitHub user id"),
    accountId: positiveInteger(input?.accountId, "GitHub installation account id"),
    accountLogin: accountLogin(input?.accountLogin),
    accountType,
  };
}

async function transaction<T>(pool: PostgresPoolLike, operation: (client: PostgresTransactionClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await operation(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {
      // Preserve the original categorical database failure.
    }
    throw error;
  } finally {
    client.release();
  }
}

export async function migrateSynSecGitHubPostgresHostedInstallationOwnership(pool: PostgresPoolLike): Promise<void> {
  await transaction(pool, async (client) => {
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", ["synsec-hosted-installation-ownership-v1"]);
    for (const statement of SYNSEC_GITHUB_POSTGRES_HOSTED_OWNERSHIP_MIGRATIONS) await client.query(statement);
  });
}

/**
 * Transactional tenant ownership store for hosted GitHub App setup.
 *
 * The installation id is the global fence: the first tenant claim wins. A second tenant can never
 * overwrite it. Re-verification by the same tenant is accepted only when the durable GitHub account
 * id/type still match; user/login churn is treated as non-authoritative metadata and does not move
 * ownership. release() is compare-and-delete by tenant id.
 */
export class PostgresSynSecHostedInstallationOwnershipStore implements SynSecHostedInstallationOwnershipStore {
  constructor(private readonly pool: PostgresPoolLike) {}

  async claim(inputValue: SynSecHostedInstallationOwnershipClaim): Promise<SynSecHostedInstallationClaimResult> {
    const input = validateClaim(inputValue);
    return transaction(this.pool, async (client) => {
      await client.query(
        "SELECT pg_advisory_xact_lock(hashtextextended('synsec-hosted-installation:' || $1::text, 0))",
        [input.installationId],
      );
      const inserted = await client.query(
        `INSERT INTO synsec_github_hosted_installation_ownership(
          installation_id, tenant_id, github_user_id, account_id, account_login, account_type
        ) VALUES ($1,$2,$3,$4,$5,$6)
        ON CONFLICT (installation_id) DO NOTHING
        RETURNING installation_id`,
        [input.installationId, input.tenantId, input.githubUserId, input.accountId, input.accountLogin, input.accountType],
      );
      if (inserted.rows.length === 1) return "claimed";

      const current = await client.query(
        `SELECT tenant_id, account_id, account_type
         FROM synsec_github_hosted_installation_ownership
         WHERE installation_id = $1`,
        [input.installationId],
      );
      const row = current.rows[0];
      if (!row || current.rows.length !== 1) throw new Error("Hosted installation ownership state is inconsistent.");
      const storedTenant = typeof row.tenant_id === "string" ? row.tenant_id : "";
      const storedAccountId = Number(row.account_id);
      const storedAccountType = row.account_type;
      if (storedTenant !== input.tenantId) return "conflict";
      if (storedAccountId !== input.accountId || storedAccountType !== input.accountType) return "conflict";
      return "already-owned-by-tenant";
    });
  }

  async release(tenantIdValue: string, installationIdValue: number): Promise<boolean> {
    const tenant = tenantId(tenantIdValue);
    const installationId = positiveInteger(installationIdValue, "GitHub installation id");
    const result = await this.pool.query(
      `DELETE FROM synsec_github_hosted_installation_ownership
       WHERE installation_id = $1 AND tenant_id = $2
       RETURNING installation_id`,
      [installationId, tenant],
    );
    return result.rows.length === 1;
  }
}
