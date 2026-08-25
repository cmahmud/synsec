import type {
  SynSecHostedInstallationOwnershipClaim,
  SynSecHostedInstallationOwnershipStore,
  SynSecHostedInstallationClaimResult,
} from "./hosted-installation-ownership.js";
import type {
  SynSecHostedInstallationReverificationFence,
  SynSecHostedInstallationReverificationFinishResult,
  SynSecHostedInstallationReverificationStore,
  SynSecHostedInstallationRevocationReason,
} from "./hosted-installation-reverification.js";
import type { PostgresPoolLike, PostgresTransactionClient } from "./postgres-shared-state.js";

const MAX_TENANT_ID_LENGTH = 128;
const MAX_LOGIN_LENGTH = 255;
const MIN_FRESHNESS_MS = 60_000;
const MAX_FRESHNESS_MS = 30 * 24 * 60 * 60 * 1000;

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
  `ALTER TABLE synsec_github_hosted_installation_ownership
    ADD COLUMN IF NOT EXISTS verification_epoch bigint NOT NULL DEFAULT 0`,
  `ALTER TABLE synsec_github_hosted_installation_ownership
    ADD COLUMN IF NOT EXISTS access_status varchar(16) NOT NULL DEFAULT 'active'`,
  `ALTER TABLE synsec_github_hosted_installation_ownership
    ADD COLUMN IF NOT EXISTS verified_at timestamptz(3)`,
  `UPDATE synsec_github_hosted_installation_ownership
    SET verified_at = claimed_at WHERE verified_at IS NULL`,
  `ALTER TABLE synsec_github_hosted_installation_ownership
    ALTER COLUMN verified_at SET NOT NULL`,
  `ALTER TABLE synsec_github_hosted_installation_ownership
    ADD COLUMN IF NOT EXISTS revoked_at timestamptz(3)`,
  `ALTER TABLE synsec_github_hosted_installation_ownership
    ADD COLUMN IF NOT EXISTS revocation_reason varchar(32)`,
  `DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'synsec_github_hosted_ownership_access_status_check'
      ) THEN
        ALTER TABLE synsec_github_hosted_installation_ownership
          ADD CONSTRAINT synsec_github_hosted_ownership_access_status_check
          CHECK (access_status IN ('active', 'revoked'));
      END IF;
    END $$`,
  `DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'synsec_github_hosted_ownership_revocation_reason_check'
      ) THEN
        ALTER TABLE synsec_github_hosted_installation_ownership
          ADD CONSTRAINT synsec_github_hosted_ownership_revocation_reason_check
          CHECK (
            revocation_reason IS NULL OR revocation_reason IN ('inaccessible', 'suspended', 'account-identity-changed')
          );
      END IF;
    END $$`,
  `CREATE INDEX IF NOT EXISTS synsec_github_hosted_installation_ownership_tenant_idx
    ON synsec_github_hosted_installation_ownership (tenant_id, installation_id)`,
] as const;

function positiveInteger(value: unknown, label: string): number {
  const normalized = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(normalized) || normalized <= 0) {
    throw new Error(`${label} must be a positive integer.`);
  }
  return normalized;
}

function nonnegativeInteger(value: unknown, label: string): number {
  const normalized = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < 0) throw new Error(`${label} must be a non-negative integer.`);
  return normalized;
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

function accountType(value: unknown): "User" | "Organization" {
  if (value !== "User" && value !== "Organization") throw new Error("GitHub installation account type is invalid.");
  return value;
}

function validateClaim(input: SynSecHostedInstallationOwnershipClaim): SynSecHostedInstallationOwnershipClaim {
  return {
    tenantId: tenantId(input?.tenantId),
    installationId: positiveInteger(input?.installationId, "GitHub installation id"),
    githubUserId: positiveInteger(input?.githubUserId, "Authenticated GitHub user id"),
    accountId: positiveInteger(input?.accountId, "GitHub installation account id"),
    accountLogin: accountLogin(input?.accountLogin),
    accountType: accountType(input?.accountType),
  };
}

function validateFence(input: SynSecHostedInstallationReverificationFence): SynSecHostedInstallationReverificationFence {
  return {
    epoch: positiveInteger(input?.epoch, "Hosted installation verification epoch"),
    tenantId: tenantId(input?.tenantId),
    installationId: positiveInteger(input?.installationId, "GitHub installation id"),
    githubUserId: positiveInteger(input?.githubUserId, "Authenticated GitHub user id"),
    accountId: positiveInteger(input?.accountId, "GitHub installation account id"),
    accountType: accountType(input?.accountType),
  };
}

function revocationReason(value: unknown): SynSecHostedInstallationRevocationReason {
  if (value !== "inaccessible" && value !== "suspended" && value !== "account-identity-changed") {
    throw new Error("Hosted installation revocation reason is invalid.");
  }
  return value;
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
 * Transactional tenant ownership store for hosted GitHub App setup and periodic re-verification.
 *
 * The installation id is the global tenant fence: revocation never deletes or transfers the claim.
 * Each remote re-verification first increments verification_epoch. Completion uses compare-and-set
 * against that epoch, so a slow result from one replica cannot overwrite a newer observation from
 * another replica. Authorization requires active state plus backend-time freshness.
 */
export class PostgresSynSecHostedInstallationOwnershipStore
implements SynSecHostedInstallationOwnershipStore, SynSecHostedInstallationReverificationStore {
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
          installation_id, tenant_id, github_user_id, account_id, account_login, account_type,
          verification_epoch, access_status, verified_at, revoked_at, revocation_reason
        ) VALUES ($1,$2,$3,$4,$5,$6,1,'active',date_trunc('milliseconds', clock_timestamp()),NULL,NULL)
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
      const storedAccountId = positiveInteger(row.account_id, "Stored GitHub installation account id");
      const storedAccountType = accountType(row.account_type);
      if (storedTenant !== input.tenantId) return "conflict";
      if (storedAccountId !== input.accountId || storedAccountType !== input.accountType) return "conflict";

      await client.query(
        `UPDATE synsec_github_hosted_installation_ownership
         SET github_user_id = $2,
             account_login = $3,
             verification_epoch = verification_epoch + 1,
             access_status = 'active',
             verified_at = date_trunc('milliseconds', clock_timestamp()),
             revoked_at = NULL,
             revocation_reason = NULL
         WHERE installation_id = $1 AND tenant_id = $4`,
        [input.installationId, input.githubUserId, input.accountLogin, input.tenantId],
      );
      return "already-owned-by-tenant";
    });
  }

  async beginReverification(
    tenantIdValue: string,
    installationIdValue: number,
    githubUserIdValue: number,
  ): Promise<SynSecHostedInstallationReverificationFence | undefined> {
    const tenant = tenantId(tenantIdValue);
    const installationId = positiveInteger(installationIdValue, "GitHub installation id");
    const githubUserId = positiveInteger(githubUserIdValue, "Authenticated GitHub user id");
    const result = await this.pool.query(
      `UPDATE synsec_github_hosted_installation_ownership
       SET verification_epoch = verification_epoch + 1
       WHERE installation_id = $1 AND tenant_id = $2 AND github_user_id = $3
       RETURNING verification_epoch, account_id, account_type`,
      [installationId, tenant, githubUserId],
    );
    if (result.rows.length === 0) return undefined;
    if (result.rows.length !== 1) throw new Error("Hosted installation ownership state is inconsistent.");
    const row = result.rows[0];
    return {
      epoch: positiveInteger(row.verification_epoch, "Hosted installation verification epoch"),
      tenantId: tenant,
      installationId,
      githubUserId,
      accountId: positiveInteger(row.account_id, "GitHub installation account id"),
      accountType: accountType(row.account_type),
    };
  }

  async finishVerified(
    inputValue: SynSecHostedInstallationReverificationFence & { accountLogin: string },
  ): Promise<SynSecHostedInstallationReverificationFinishResult> {
    const input = validateFence(inputValue);
    const login = accountLogin(inputValue.accountLogin);
    const result = await this.pool.query(
      `UPDATE synsec_github_hosted_installation_ownership
       SET account_login = $7,
           access_status = 'active',
           verified_at = date_trunc('milliseconds', clock_timestamp()),
           revoked_at = NULL,
           revocation_reason = NULL
       WHERE installation_id = $1 AND tenant_id = $2 AND github_user_id = $3
         AND verification_epoch = $4 AND account_id = $5 AND account_type = $6
       RETURNING installation_id`,
      [input.installationId, input.tenantId, input.githubUserId, input.epoch, input.accountId, input.accountType, login],
    );
    if (result.rows.length === 1) return "applied";
    return this.classifyMiss(input);
  }

  async finishRevoked(
    inputValue: SynSecHostedInstallationReverificationFence & { reason: SynSecHostedInstallationRevocationReason },
  ): Promise<SynSecHostedInstallationReverificationFinishResult> {
    const input = validateFence(inputValue);
    const reason = revocationReason(inputValue.reason);
    const result = await this.pool.query(
      `UPDATE synsec_github_hosted_installation_ownership
       SET access_status = 'revoked',
           revoked_at = date_trunc('milliseconds', clock_timestamp()),
           revocation_reason = $7
       WHERE installation_id = $1 AND tenant_id = $2 AND github_user_id = $3
         AND verification_epoch = $4 AND account_id = $5 AND account_type = $6
       RETURNING installation_id`,
      [input.installationId, input.tenantId, input.githubUserId, input.epoch, input.accountId, input.accountType, reason],
    );
    if (result.rows.length === 1) return "applied";
    return this.classifyMiss(input);
  }

  async isFreshlyAuthorized(tenantIdValue: string, installationIdValue: number, maxAgeMsValue: number): Promise<boolean> {
    const tenant = tenantId(tenantIdValue);
    const installationId = positiveInteger(installationIdValue, "GitHub installation id");
    if (!Number.isSafeInteger(maxAgeMsValue) || maxAgeMsValue < MIN_FRESHNESS_MS || maxAgeMsValue > MAX_FRESHNESS_MS) {
      throw new Error(`Hosted installation verification freshness must be between ${MIN_FRESHNESS_MS} and ${MAX_FRESHNESS_MS} milliseconds.`);
    }
    const result = await this.pool.query(
      `SELECT EXISTS(
         SELECT 1 FROM synsec_github_hosted_installation_ownership
         WHERE installation_id = $1 AND tenant_id = $2 AND access_status = 'active'
           AND verified_at > clock_timestamp() - ($3::bigint * interval '1 millisecond')
       ) AS allowed`,
      [installationId, tenant, maxAgeMsValue],
    );
    return result.rows[0]?.allowed === true;
  }

  private async classifyMiss(
    input: SynSecHostedInstallationReverificationFence,
  ): Promise<SynSecHostedInstallationReverificationFinishResult> {
    const current = await this.pool.query(
      `SELECT tenant_id, github_user_id, account_id, account_type, verification_epoch
       FROM synsec_github_hosted_installation_ownership WHERE installation_id = $1`,
      [input.installationId],
    );
    if (current.rows.length !== 1) return "conflict";
    const row = current.rows[0];
    if (row.tenant_id !== input.tenantId
      || positiveInteger(row.github_user_id, "Stored GitHub user id") !== input.githubUserId
      || positiveInteger(row.account_id, "Stored GitHub installation account id") !== input.accountId
      || accountType(row.account_type) !== input.accountType) return "conflict";
    const epoch = nonnegativeInteger(row.verification_epoch, "Hosted installation verification epoch");
    return epoch !== input.epoch ? "stale" : "conflict";
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
