import { randomBytes } from "node:crypto";
import type { GitHubWebhookDeliveryClaim } from "./replay-store.js";
import type { GitHubScanJob, GitHubScanJobInput, GitHubScanJobStatus } from "./scan-queue.js";

const MAX_QUEUE_ENTRIES = 10_000;
const MAX_ATTEMPTS = 5;
const DEFAULT_LEASE_MS = 5 * 60 * 1000;
const MIN_LEASE_MS = 10_000;
const MAX_LEASE_MS = 60 * 60 * 1000;
const DEFAULT_REPLAY_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const MIN_REPLAY_RETENTION_MS = 60 * 60 * 1000;
const MAX_REPLAY_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_PRUNE_BATCH = 10_000;
const ENQUEUE_ADVISORY_LOCK = 1_938_211_067;

export interface PostgresQueryResult {
  rows: Array<Record<string, unknown>>;
  rowCount?: number | null;
}

export interface PostgresQueryable {
  query(text: string, values?: unknown[]): Promise<PostgresQueryResult>;
}

export interface PostgresTransactionClient extends PostgresQueryable {
  release(): void;
}

export interface PostgresPoolLike extends PostgresQueryable {
  connect(): Promise<PostgresTransactionClient>;
}

export interface PostgresGitHubSharedStateOptions {
  replayRetentionMs?: number;
  leaseMs?: number;
}

export const SYNSEC_GITHUB_POSTGRES_SCHEMA_VERSION = 1 as const;

export const SYNSEC_GITHUB_POSTGRES_MIGRATIONS = [
  `CREATE TABLE IF NOT EXISTS synsec_github_schema (
    component text PRIMARY KEY,
    version integer NOT NULL CHECK (version > 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
  )`,
  `CREATE TABLE IF NOT EXISTS synsec_github_replay (
    delivery_id varchar(128) PRIMARY KEY,
    received_at timestamptz(3) NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS synsec_github_scan_jobs (
    job_id char(32) PRIMARY KEY,
    delivery_id varchar(128) NOT NULL UNIQUE,
    installation_id bigint NOT NULL CHECK (installation_id > 0),
    repository varchar(255) NOT NULL,
    head_sha varchar(64) NOT NULL,
    event varchar(32) NOT NULL CHECK (event IN ('push', 'pull_request')),
    base_sha varchar(64),
    pull_request_number integer CHECK (pull_request_number > 0),
    created_at timestamptz NOT NULL,
    attempts smallint NOT NULL DEFAULT 0 CHECK (attempts >= 0 AND attempts <= 5),
    status varchar(16) NOT NULL CHECK (status IN ('pending', 'leased', 'failed')),
    lease_until timestamptz,
    lease_id char(32),
    CHECK (
      (event = 'pull_request' AND base_sha IS NOT NULL AND pull_request_number IS NOT NULL)
      OR (event = 'push' AND base_sha IS NULL AND pull_request_number IS NULL)
    ),
    CHECK (
      (status = 'leased' AND lease_until IS NOT NULL AND lease_id IS NOT NULL)
      OR (status <> 'leased' AND lease_until IS NULL AND lease_id IS NULL)
    )
  )`,
  `CREATE INDEX IF NOT EXISTS synsec_github_scan_jobs_claim_idx
    ON synsec_github_scan_jobs (status, lease_until, created_at, job_id)`,
] as const;

function integerInRange(value: number | undefined, fallback: number, minimum: number, maximum: number, label: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < minimum || resolved > maximum) {
    throw new Error(`${label} must be an integer between ${minimum} and ${maximum} milliseconds.`);
  }
  return resolved;
}

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

function deliveryId(value: unknown): string {
  const normalized = boundedString(value, "GitHub delivery id", 128);
  if (!/^[A-Za-z0-9._:-]+$/.test(normalized)) throw new Error("GitHub delivery id contains unsupported characters.");
  return normalized;
}

function repository(value: unknown): string {
  const normalized = boundedString(value, "GitHub repository", 255);
  if (!/^[^/\s]+\/[^/\s]+$/.test(normalized)) throw new Error("GitHub repository must be in owner/name form.");
  return normalized;
}

function commitSha(value: unknown, label: string): string {
  const normalized = boundedString(value, label, 64).toLowerCase();
  if (!/^[a-f0-9]{40,64}$/.test(normalized)) throw new Error(`${label} must be a hexadecimal commit SHA.`);
  return normalized;
}

function jobId(value: unknown): string {
  const normalized = boundedString(value, "GitHub scan job id", 32).toLowerCase();
  if (!/^[a-f0-9]{32}$/.test(normalized)) throw new Error("GitHub scan job id is invalid.");
  return normalized;
}

function leaseId(value: unknown): string {
  const normalized = boundedString(value, "GitHub scan job lease id", 32).toLowerCase();
  if (!/^[a-f0-9]{32}$/.test(normalized)) throw new Error("GitHub scan job lease id is invalid.");
  return normalized;
}

function timestamp(value: unknown, label: string): string {
  if (value instanceof Date) return value.toISOString();
  const normalized = boundedString(value, label, 64);
  if (!Number.isFinite(Date.parse(normalized))) throw new Error(`${label} must be an ISO timestamp.`);
  return new Date(normalized).toISOString();
}

function rowString(row: Record<string, unknown>, key: string): unknown {
  return row[key];
}

function jobFromRow(row: Record<string, unknown>): GitHubScanJob {
  const event = rowString(row, "event");
  if (event !== "push" && event !== "pull_request") throw new Error("PostgreSQL scan job has an invalid event type.");
  const status = rowString(row, "status");
  if (status !== "pending" && status !== "leased" && status !== "failed") throw new Error("PostgreSQL scan job has an invalid status.");
  const attemptsValue = rowString(row, "attempts");
  const attempts = typeof attemptsValue === "number" ? attemptsValue : Number(attemptsValue);
  if (!Number.isSafeInteger(attempts) || attempts < 0 || attempts > MAX_ATTEMPTS) throw new Error("PostgreSQL scan job has an invalid attempt count.");
  const installationValue = rowString(row, "installation_id");
  const installationId = typeof installationValue === "number" ? installationValue : Number(installationValue);
  const pullRequestValue = rowString(row, "pull_request_number");
  const pullRequestNumber = pullRequestValue === null || pullRequestValue === undefined
    ? undefined
    : positiveInteger(typeof pullRequestValue === "number" ? pullRequestValue : Number(pullRequestValue), "GitHub pull request number");
  const baseValue = rowString(row, "base_sha");
  const baseSha = baseValue === null || baseValue === undefined ? undefined : commitSha(baseValue, "GitHub base SHA");
  const leaseUntilValue = rowString(row, "lease_until");
  const leaseIdentityValue = rowString(row, "lease_id");
  const leaseUntil = leaseUntilValue === null || leaseUntilValue === undefined ? undefined : timestamp(leaseUntilValue, "GitHub scan job leaseUntil");
  const currentLeaseId = leaseIdentityValue === null || leaseIdentityValue === undefined ? undefined : leaseId(leaseIdentityValue);
  if (status === "leased" && (!leaseUntil || !currentLeaseId)) throw new Error("PostgreSQL leased scan job is missing lease metadata.");
  if (status !== "leased" && (leaseUntil || currentLeaseId)) throw new Error("PostgreSQL non-leased scan job contains lease metadata.");
  return {
    version: 1,
    jobId: jobId(rowString(row, "job_id")),
    deliveryId: deliveryId(rowString(row, "delivery_id")),
    installationId: positiveInteger(installationId, "GitHub installation id"),
    repository: repository(rowString(row, "repository")),
    headSha: commitSha(rowString(row, "head_sha"), "GitHub head SHA"),
    event,
    ...(baseSha ? { baseSha } : {}),
    ...(pullRequestNumber ? { pullRequestNumber } : {}),
    createdAt: timestamp(rowString(row, "created_at"), "GitHub scan job createdAt"),
    attempts,
    status,
    ...(leaseUntil ? { leaseUntil } : {}),
    ...(currentLeaseId ? { leaseId: currentLeaseId } : {}),
  };
}

function matchesLogicalJob(
  existing: GitHubScanJob,
  input: {
    installationId: number;
    repository: string;
    headSha: string;
    event: GitHubScanJob["event"];
    baseSha?: string;
    pullRequestNumber?: number;
  },
): boolean {
  return existing.installationId === input.installationId
    && existing.repository === input.repository
    && existing.headSha === input.headSha
    && existing.event === input.event
    && existing.baseSha === input.baseSha
    && existing.pullRequestNumber === input.pullRequestNumber;
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
      // Preserve the original database failure; rollback diagnostics may contain connection details.
    }
    throw error;
  } finally {
    client.release();
  }
}

export async function migrateSynSecGitHubPostgresState(pool: PostgresPoolLike): Promise<void> {
  await transaction(pool, async (client) => {
    for (const statement of SYNSEC_GITHUB_POSTGRES_MIGRATIONS) await client.query(statement);
    const current = await client.query("SELECT version FROM synsec_github_schema WHERE component = $1 FOR UPDATE", ["shared-state"]);
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
  });
}

export class PostgresGitHubWebhookReplayStore {
  readonly retentionMs: number;
  constructor(private readonly pool: PostgresPoolLike, options: PostgresGitHubSharedStateOptions = {}) {
    this.retentionMs = integerInRange(
      options.replayRetentionMs,
      DEFAULT_REPLAY_RETENTION_MS,
      MIN_REPLAY_RETENTION_MS,
      MAX_REPLAY_RETENTION_MS,
      "Webhook replay retention",
    );
  }

  async claim(deliveryIdValue: string): Promise<GitHubWebhookDeliveryClaim> {
    const id = deliveryId(deliveryIdValue);
    return transaction(this.pool, async (client) => {
      await client.query(
        "SELECT pg_advisory_xact_lock(hashtextextended('synsec-replay:' || $1::text, 0))",
        [id],
      );
      const existing = await client.query(
        "SELECT received_at FROM synsec_github_replay WHERE delivery_id = $1 FOR UPDATE",
        [id],
      );
      const row = existing.rows[0];
      if (row) {
        const receivedAt = timestamp(row.received_at, "GitHub webhook replay receivedAt");
        const fresh = await client.query(
          `SELECT $1::timestamptz > clock_timestamp() - ($2::bigint * interval '1 millisecond') AS fresh`,
          [receivedAt, this.retentionMs],
        );
        if (fresh.rows[0]?.fresh === true) {
          return { accepted: false, deliveryId: id, receivedAt };
        }
        const reclaimed = await client.query(
          `UPDATE synsec_github_replay
           SET received_at = date_trunc('milliseconds', clock_timestamp())
           WHERE delivery_id = $1
           RETURNING received_at`,
          [id],
        );
        const reclaimedRow = reclaimed.rows[0];
        if (!reclaimedRow) throw new Error("PostgreSQL replay reclaim did not return durable state.");
        return {
          accepted: true,
          deliveryId: id,
          receivedAt: timestamp(reclaimedRow.received_at, "GitHub webhook replay receivedAt"),
        };
      }

      const inserted = await client.query(
        `INSERT INTO synsec_github_replay(delivery_id, received_at)
         VALUES ($1, date_trunc('milliseconds', clock_timestamp()))
         RETURNING received_at`,
        [id],
      );
      const insertedRow = inserted.rows[0];
      if (!insertedRow) throw new Error("PostgreSQL replay claim did not return durable state.");
      return {
        accepted: true,
        deliveryId: id,
        receivedAt: timestamp(insertedRow.received_at, "GitHub webhook replay receivedAt"),
      };
    });
  }

  async release(deliveryIdValue: string, receivedAtValue: string): Promise<boolean> {
    const id = deliveryId(deliveryIdValue);
    const receivedAt = timestamp(receivedAtValue, "GitHub webhook replay receivedAt");
    const result = await this.pool.query(
      `DELETE FROM synsec_github_replay
       WHERE delivery_id = $1
         AND received_at = $2::timestamptz
         AND received_at > clock_timestamp() - ($3::bigint * interval '1 millisecond')
       RETURNING delivery_id`,
      [id, receivedAt, this.retentionMs],
    );
    return result.rows.length === 1;
  }

  async pruneExpired(limit = MAX_PRUNE_BATCH): Promise<number> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_PRUNE_BATCH) {
      throw new Error(`PostgreSQL replay prune limit must be between 1 and ${MAX_PRUNE_BATCH}.`);
    }
    const result = await this.pool.query(
      `WITH expired AS (
        SELECT delivery_id FROM synsec_github_replay
        WHERE received_at <= clock_timestamp() - ($1::bigint * interval '1 millisecond')
        ORDER BY received_at, delivery_id
        FOR UPDATE SKIP LOCKED
        LIMIT $2
      )
      DELETE FROM synsec_github_replay replay
      USING expired
      WHERE replay.delivery_id = expired.delivery_id
      RETURNING replay.delivery_id`,
      [this.retentionMs, limit],
    );
    return result.rows.length;
  }
}

export class PostgresGitHubScanQueue {
  readonly leaseMs: number;
  constructor(private readonly pool: PostgresPoolLike, options: PostgresGitHubSharedStateOptions = {}) {
    this.leaseMs = integerInRange(options.leaseMs, DEFAULT_LEASE_MS, MIN_LEASE_MS, MAX_LEASE_MS, "GitHub scan job lease");
  }

  async enqueue(input: GitHubScanJobInput): Promise<GitHubScanJob> {
    const event = input.event;
    if (event !== "push" && event !== "pull_request") throw new Error("GitHub scan job event must be push or pull_request.");
    const id = randomBytes(16).toString("hex");
    const delivery = deliveryId(input.deliveryId);
    const installationId = positiveInteger(input.installationId, "GitHub installation id");
    const repo = repository(input.repository);
    const headSha = commitSha(input.headSha, "GitHub head SHA");
    const baseSha = input.baseSha === undefined ? undefined : commitSha(input.baseSha, "GitHub base SHA");
    const pullRequestNumber = input.pullRequestNumber === undefined ? undefined : positiveInteger(input.pullRequestNumber, "GitHub pull request number");
    if (event === "pull_request" && (!baseSha || !pullRequestNumber)) throw new Error("Pull request scan jobs require base SHA and pull request number.");
    if (event === "push" && (baseSha || pullRequestNumber)) throw new Error("Push scan jobs must not contain pull request metadata.");
    const createdAt = input.createdAt === undefined ? undefined : timestamp(input.createdAt, "GitHub scan job createdAt");

    return transaction(this.pool, async (client) => {
      await client.query("SELECT pg_advisory_xact_lock($1)", [ENQUEUE_ADVISORY_LOCK]);
      const existingResult = await client.query(
        "SELECT * FROM synsec_github_scan_jobs WHERE delivery_id = $1",
        [delivery],
      );
      if (existingResult.rows.length > 1) throw new Error("PostgreSQL scan queue contains duplicate delivery ids.");
      const existingRow = existingResult.rows[0];
      if (existingRow) {
        const existing = jobFromRow(existingRow);
        if (!matchesLogicalJob(existing, {
          installationId,
          repository: repo,
          headSha,
          event,
          ...(baseSha ? { baseSha } : {}),
          ...(pullRequestNumber ? { pullRequestNumber } : {}),
        })) {
          throw new Error("GitHub delivery id is already queued with different scan provenance.");
        }
        return existing;
      }

      const countResult = await client.query("SELECT count(*)::integer AS count FROM synsec_github_scan_jobs");
      const count = Number(countResult.rows[0]?.count);
      if (!Number.isSafeInteger(count) || count < 0) throw new Error("PostgreSQL scan queue returned an invalid job count.");
      if (count >= MAX_QUEUE_ENTRIES) throw new Error(`GitHub scan queue reached the ${MAX_QUEUE_ENTRIES}-job limit.`);
      const result = await client.query(
        `INSERT INTO synsec_github_scan_jobs(
          job_id, delivery_id, installation_id, repository, head_sha, event, base_sha,
          pull_request_number, created_at, attempts, status
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,COALESCE($9::timestamptz, clock_timestamp()),0,'pending')
        RETURNING *`,
        [id, delivery, installationId, repo, headSha, event, baseSha ?? null, pullRequestNumber ?? null, createdAt ?? null],
      );
      const row = result.rows[0];
      if (!row) throw new Error("PostgreSQL scan queue insertion did not return durable state.");
      return jobFromRow(row);
    });
  }

  async claimNext(): Promise<GitHubScanJob | undefined> {
    for (let examined = 0; examined <= MAX_QUEUE_ENTRIES; examined += 1) {
      const nextLeaseId = randomBytes(16).toString("hex");
      const result = await this.pool.query(
        `WITH candidate AS (
          SELECT job_id FROM synsec_github_scan_jobs
          WHERE status = 'pending' OR (status = 'leased' AND lease_until <= clock_timestamp())
          ORDER BY created_at, job_id
          FOR UPDATE SKIP LOCKED
          LIMIT 1
        )
        UPDATE synsec_github_scan_jobs jobs
        SET attempts = CASE WHEN jobs.attempts >= $2 THEN jobs.attempts ELSE jobs.attempts + 1 END,
            status = CASE WHEN jobs.attempts >= $2 THEN 'failed' ELSE 'leased' END,
            lease_until = CASE WHEN jobs.attempts >= $2 THEN NULL ELSE clock_timestamp() + ($3::bigint * interval '1 millisecond') END,
            lease_id = CASE WHEN jobs.attempts >= $2 THEN NULL ELSE $1 END
        FROM candidate
        WHERE jobs.job_id = candidate.job_id
        RETURNING jobs.*`,
        [nextLeaseId, MAX_ATTEMPTS, this.leaseMs],
      );
      const row = result.rows[0];
      if (!row) return undefined;
      const job = jobFromRow(row);
      if (job.status === "failed") continue;
      return job;
    }
    throw new Error("PostgreSQL scan queue exceeded its bounded claim search.");
  }

  async assertLease(jobIdValue: string, expectedLeaseId: string): Promise<GitHubScanJob> {
    const result = await this.pool.query(
      `SELECT * FROM synsec_github_scan_jobs
       WHERE job_id = $1 AND status = 'leased' AND lease_id = $2 AND lease_until > clock_timestamp()`,
      [jobId(jobIdValue), leaseId(expectedLeaseId)],
    );
    const row = result.rows[0];
    if (!row) throw new Error("GitHub scan job lease is stale, expired, or no longer owned by this worker.");
    return jobFromRow(row);
  }

  async renew(jobIdValue: string, expectedLeaseId: string): Promise<GitHubScanJob> {
    const result = await this.pool.query(
      `UPDATE synsec_github_scan_jobs
       SET lease_until = clock_timestamp() + ($3::bigint * interval '1 millisecond')
       WHERE job_id = $1 AND status = 'leased' AND lease_id = $2 AND lease_until > clock_timestamp()
       RETURNING *`,
      [jobId(jobIdValue), leaseId(expectedLeaseId), this.leaseMs],
    );
    const row = result.rows[0];
    if (!row) throw new Error("GitHub scan job lease is stale, expired, or no longer owned by this worker.");
    return jobFromRow(row);
  }

  async release(jobIdValue: string, expectedLeaseId: string): Promise<GitHubScanJob> {
    return this.transition(jobIdValue, expectedLeaseId, "pending");
  }

  async fail(jobIdValue: string, expectedLeaseId: string): Promise<GitHubScanJob> {
    return this.transition(jobIdValue, expectedLeaseId, "failed");
  }

  private async transition(jobIdValue: string, expectedLeaseId: string, status: Exclude<GitHubScanJobStatus, "leased">): Promise<GitHubScanJob> {
    const result = await this.pool.query(
      `UPDATE synsec_github_scan_jobs
       SET status = $3, lease_until = NULL, lease_id = NULL
       WHERE job_id = $1 AND status = 'leased' AND lease_id = $2 AND lease_until > clock_timestamp()
       RETURNING *`,
      [jobId(jobIdValue), leaseId(expectedLeaseId), status],
    );
    const row = result.rows[0];
    if (!row) throw new Error("GitHub scan job lease is stale, expired, or no longer owned by this worker.");
    return jobFromRow(row);
  }

  async complete(jobIdValue: string, expectedLeaseId: string): Promise<boolean> {
    const id = jobId(jobIdValue);
    const expected = leaseId(expectedLeaseId);
    const result = await this.pool.query(
      `DELETE FROM synsec_github_scan_jobs
       WHERE job_id = $1 AND status = 'leased' AND lease_id = $2 AND lease_until > clock_timestamp()
       RETURNING job_id`,
      [id, expected],
    );
    if (result.rows.length === 1) return true;
    const exists = await this.pool.query("SELECT job_id FROM synsec_github_scan_jobs WHERE job_id = $1", [id]);
    if (exists.rows.length > 0) throw new Error("GitHub scan job lease is stale, expired, or no longer owned by this worker.");
    return false;
  }

  async list(): Promise<GitHubScanJob[]> {
    const result = await this.pool.query(
      `SELECT * FROM synsec_github_scan_jobs ORDER BY created_at, job_id LIMIT $1`,
      [MAX_QUEUE_ENTRIES + 1],
    );
    if (result.rows.length > MAX_QUEUE_ENTRIES) throw new Error(`GitHub scan queue exceeds the ${MAX_QUEUE_ENTRIES}-job limit.`);
    return result.rows.map(jobFromRow);
  }

  async deleteFailed(jobIdValue: string): Promise<boolean> {
    const result = await this.pool.query(
      `DELETE FROM synsec_github_scan_jobs WHERE job_id = $1 AND status = 'failed' RETURNING job_id`,
      [jobId(jobIdValue)],
    );
    return result.rows.length === 1;
  }
}
