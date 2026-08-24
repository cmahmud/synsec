import type {
  GitHubInstallationRecord,
  GitHubInstallationRecordInput,
} from "./installation-store.js";
import type {
  GitHubInstallationStateStore,
  GitHubTransactionalInstallationStateStore,
} from "./installation-sync.js";
import type {
  PostgresPoolLike,
  PostgresQueryResult,
  PostgresQueryable,
  PostgresTransactionClient,
} from "./postgres-shared-state.js";
import { validateGitHubRepositoryIdentity } from "./repository-acquisition.js";

const MAX_REPOSITORY_COUNT = 10_000;
const MAX_LOGIN_LENGTH = 255;

export const SYNSEC_GITHUB_POSTGRES_INSTALLATION_MIGRATIONS = [
  `CREATE TABLE IF NOT EXISTS synsec_github_installations (
    installation_id bigint PRIMARY KEY CHECK (installation_id > 0),
    account_login varchar(255) NOT NULL,
    account_type varchar(16) NOT NULL CHECK (account_type IN ('User', 'Organization')),
    repository_selection varchar(16) NOT NULL CHECK (repository_selection IN ('all', 'selected')),
    repositories text[] NOT NULL DEFAULT ARRAY[]::text[],
    suspended_at timestamptz(3),
    updated_at timestamptz(3) NOT NULL,
    CHECK (repository_selection = 'selected' OR cardinality(repositories) = 0),
    CHECK (cardinality(repositories) <= 10000)
  )`,
] as const;

function positiveInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer.`);
  }
  return value;
}

function boundedString(value: unknown, label: string, maximum: number): string {
  if (typeof value !== "string") throw new Error(`${label} must be a string.`);
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required.`);
  if (normalized.length > maximum) throw new Error(`${label} exceeds ${maximum} characters.`);
  if (/[\u0000-\u001f\u007f]/.test(normalized)) throw new Error(`${label} contains unsupported control characters.`);
  return normalized;
}

function timestamp(value: unknown, label: string): string {
  if (value instanceof Date) return value.toISOString();
  const normalized = boundedString(value, label, 64);
  if (!Number.isFinite(Date.parse(normalized))) throw new Error(`${label} must be an ISO timestamp.`);
  return new Date(normalized).toISOString();
}

function normalize(input: GitHubInstallationRecordInput | GitHubInstallationRecord): GitHubInstallationRecord {
  const installationId = positiveInteger(input.installationId, "GitHub installation id");
  const accountLogin = boundedString(input.accountLogin, "GitHub account login", MAX_LOGIN_LENGTH);
  if (input.accountType !== "User" && input.accountType !== "Organization") {
    throw new Error("GitHub installation account type must be User or Organization.");
  }
  if (input.repositorySelection !== "all" && input.repositorySelection !== "selected") {
    throw new Error("GitHub repository selection must be all or selected.");
  }
  const sourceRepositories = input.repositories ?? [];
  if (!Array.isArray(sourceRepositories) || sourceRepositories.length > MAX_REPOSITORY_COUNT) {
    throw new Error(`GitHub installation repositories exceed the ${MAX_REPOSITORY_COUNT}-entry limit.`);
  }
  const repositories = [...new Set(sourceRepositories.map((value) => validateGitHubRepositoryIdentity(
    boundedString(value, "GitHub repository", 255),
  )))].sort();
  if (input.repositorySelection === "all" && repositories.length > 0) {
    throw new Error("GitHub installations with repositorySelection=all must not persist an enumerated repository list.");
  }
  const updatedAt = timestamp(input.updatedAt ?? new Date().toISOString(), "GitHub installation updatedAt");
  const suspendedAt = input.suspendedAt === undefined ? undefined : timestamp(input.suspendedAt, "GitHub installation suspendedAt");
  return {
    version: 1,
    installationId,
    accountLogin,
    accountType: input.accountType,
    repositorySelection: input.repositorySelection,
    repositories,
    ...(suspendedAt ? { suspendedAt } : {}),
    updatedAt,
  };
}

function recordFromRow(row: Record<string, unknown>): GitHubInstallationRecord {
  const repositories = row.repositories;
  if (!Array.isArray(repositories) || repositories.some((value) => typeof value !== "string")) {
    throw new Error("PostgreSQL installation state contains an invalid repository list.");
  }
  return normalize({
    version: 1,
    installationId: positiveInteger(
      typeof row.installation_id === "number" ? row.installation_id : Number(row.installation_id),
      "GitHub installation id",
    ),
    accountLogin: boundedString(row.account_login, "GitHub account login", MAX_LOGIN_LENGTH),
    accountType: row.account_type as GitHubInstallationRecord["accountType"],
    repositorySelection: row.repository_selection as GitHubInstallationRecord["repositorySelection"],
    repositories,
    ...(row.suspended_at === null || row.suspended_at === undefined
      ? {}
      : { suspendedAt: timestamp(row.suspended_at, "GitHub installation suspendedAt") }),
    updatedAt: timestamp(row.updated_at, "GitHub installation updatedAt"),
  });
}

async function transaction<T>(
  pool: PostgresPoolLike,
  operation: (client: PostgresTransactionClient) => Promise<T>,
): Promise<T> {
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
      // Preserve the original backend failure; rollback diagnostics may contain connection details.
    }
    throw error;
  } finally {
    client.release();
  }
}

export async function migrateSynSecGitHubPostgresInstallationState(pool: PostgresPoolLike): Promise<void> {
  await transaction(pool, async (client) => {
    for (const statement of SYNSEC_GITHUB_POSTGRES_INSTALLATION_MIGRATIONS) await client.query(statement);
  });
}

/**
 * Shared PostgreSQL installation authorization state.
 *
 * The root store owns no credentials; its caller owns the database pool. Installation webhook
 * read-modify-write operations use withInstallationTransaction(), which acquires one transaction-
 * scoped advisory lock derived from the installation id and executes all reads/writes on the same
 * database connection. Authorization checks always query shared durable state afresh.
 */
export class PostgresGitHubInstallationStore implements GitHubTransactionalInstallationStateStore {
  private readonly queryable: PostgresQueryable;

  constructor(
    private readonly pool: PostgresPoolLike,
    queryable?: PostgresQueryable,
  ) {
    this.queryable = queryable ?? pool;
  }

  async withInstallationTransaction<T>(
    installationIdValue: number,
    operation: (store: GitHubInstallationStateStore) => Promise<T>,
  ): Promise<T> {
    const installationId = positiveInteger(installationIdValue, "GitHub installation id");
    return transaction(this.pool, async (client) => {
      await client.query(
        "SELECT pg_advisory_xact_lock(hashtextextended('synsec-installation:' || $1::text, 0))",
        [installationId],
      );
      return operation(new PostgresGitHubInstallationStore(this.pool, client));
    });
  }

  async put(input: GitHubInstallationRecordInput): Promise<GitHubInstallationRecord> {
    const record = normalize(input);
    const result = await this.queryable.query(
      `INSERT INTO synsec_github_installations(
        installation_id, account_login, account_type, repository_selection,
        repositories, suspended_at, updated_at
      ) VALUES ($1,$2,$3,$4,$5::text[],$6::timestamptz,$7::timestamptz)
      ON CONFLICT (installation_id) DO UPDATE SET
        account_login = EXCLUDED.account_login,
        account_type = EXCLUDED.account_type,
        repository_selection = EXCLUDED.repository_selection,
        repositories = EXCLUDED.repositories,
        suspended_at = EXCLUDED.suspended_at,
        updated_at = EXCLUDED.updated_at
      RETURNING *`,
      [
        record.installationId,
        record.accountLogin,
        record.accountType,
        record.repositorySelection,
        record.repositories,
        record.suspendedAt ?? null,
        record.updatedAt,
      ],
    );
    const row = result.rows[0];
    if (!row) throw new Error("PostgreSQL installation update did not return durable state.");
    return recordFromRow(row);
  }

  async get(installationIdValue: number): Promise<GitHubInstallationRecord | undefined> {
    const installationId = positiveInteger(installationIdValue, "GitHub installation id");
    const result = await this.queryable.query(
      "SELECT * FROM synsec_github_installations WHERE installation_id = $1",
      [installationId],
    );
    if (result.rows.length > 1) throw new Error("PostgreSQL installation state contains duplicate installation ids.");
    const row = result.rows[0];
    return row ? recordFromRow(row) : undefined;
  }

  async remove(installationIdValue: number): Promise<boolean> {
    const installationId = positiveInteger(installationIdValue, "GitHub installation id");
    const result = await this.queryable.query(
      "DELETE FROM synsec_github_installations WHERE installation_id = $1 RETURNING installation_id",
      [installationId],
    );
    return result.rows.length === 1;
  }

  async isRepositoryAllowed(installationIdValue: number, repositoryValue: string): Promise<boolean> {
    const installationId = positiveInteger(installationIdValue, "GitHub installation id");
    const repository = validateGitHubRepositoryIdentity(boundedString(repositoryValue, "GitHub repository", 255));
    const result: PostgresQueryResult = await this.queryable.query(
      `SELECT repository_selection, repositories, suspended_at
       FROM synsec_github_installations
       WHERE installation_id = $1`,
      [installationId],
    );
    const row = result.rows[0];
    if (!row || row.suspended_at !== null && row.suspended_at !== undefined) return false;
    if (row.repository_selection === "all") return true;
    if (row.repository_selection !== "selected" || !Array.isArray(row.repositories)) {
      throw new Error("PostgreSQL installation authorization state has an invalid shape.");
    }
    return row.repositories.some((value) => value === repository);
  }
}
