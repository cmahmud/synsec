import type { GitHubScanJob } from "./scan-queue.js";
import { FileGitHubScanQueue } from "./scan-queue.js";

const DEFAULT_FAILED_JOB_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const MIN_FAILED_JOB_RETENTION_MS = 60 * 60 * 1000;
const MAX_FAILED_JOB_RETENTION_MS = 180 * 24 * 60 * 60 * 1000;

export interface GitHubAppRetentionOptions {
  failedJobRetentionMs?: number;
  maxDeletes?: number;
  now?: () => number;
}

export interface GitHubAppRetentionResult {
  inspected: number;
  deleted: number;
  retainedFailed: number;
}

function boundedRetention(value: number | undefined): number {
  const retention = value ?? DEFAULT_FAILED_JOB_RETENTION_MS;
  if (
    !Number.isSafeInteger(retention) ||
    retention < MIN_FAILED_JOB_RETENTION_MS ||
    retention > MAX_FAILED_JOB_RETENTION_MS
  ) {
    throw new Error(
      `Failed GitHub scan-job retention must be between ${MIN_FAILED_JOB_RETENTION_MS} and ${MAX_FAILED_JOB_RETENTION_MS} milliseconds.`,
    );
  }
  return retention;
}

function boundedDeletes(value: number | undefined): number {
  const maxDeletes = value ?? 100;
  if (!Number.isSafeInteger(maxDeletes) || maxDeletes < 1 || maxDeletes > 1_000) {
    throw new Error("GitHub App retention maxDeletes must be between 1 and 1000.");
  }
  return maxDeletes;
}

function jobCreatedAt(job: GitHubScanJob): number {
  const parsed = Date.parse(job.createdAt);
  if (!Number.isFinite(parsed)) throw new Error("Stored GitHub scan job has an invalid createdAt timestamp.");
  return parsed;
}

/**
 * Delete only terminal failed queue records older than the configured retention window.
 *
 * Pending and leased work is never deleted, even when old. Deletion is capped per invocation so
 * operator maintenance cannot turn into an unbounded filesystem sweep. The queue validates every
 * record before this function sees it, so malformed durable state continues to fail closed.
 */
export async function pruneGitHubAppFailedJobs(
  queue: FileGitHubScanQueue,
  options: GitHubAppRetentionOptions = {},
): Promise<GitHubAppRetentionResult> {
  const retentionMs = boundedRetention(options.failedJobRetentionMs);
  const maxDeletes = boundedDeletes(options.maxDeletes);
  const now = (options.now ?? Date.now)();
  if (!Number.isFinite(now) || now <= 0) throw new Error("GitHub App retention clock must be a positive timestamp.");

  const jobs = await queue.list();
  let deleted = 0;
  let retainedFailed = 0;

  for (const job of jobs) {
    if (job.status !== "failed") continue;
    const expired = jobCreatedAt(job) <= now - retentionMs;
    if (!expired || deleted >= maxDeletes) {
      retainedFailed += 1;
      continue;
    }
    if (await queue.complete(job.jobId)) deleted += 1;
  }

  return { inspected: jobs.length, deleted, retainedFailed };
}
