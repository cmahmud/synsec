import { randomBytes } from "node:crypto";
import { lstat, open, readFile, readdir, rename, rm, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { ensurePrivateDirectory } from "./private-directory.js";

const MAX_JOB_BYTES = 16 * 1024;
const MAX_QUEUE_ENTRIES = 10_000;
const DEFAULT_LEASE_MS = 5 * 60 * 1000;
const MIN_LEASE_MS = 10_000;
const MAX_LEASE_MS = 60 * 60 * 1000;
const MAX_ATTEMPTS = 5;

export type GitHubScanJobEvent = "push" | "pull_request";
export type GitHubScanJobStatus = "pending" | "leased" | "failed";

export interface GitHubScanJobInput {
  deliveryId: string;
  installationId: number;
  repository: string;
  headSha: string;
  event: GitHubScanJobEvent;
  baseSha?: string;
  pullRequestNumber?: number;
  createdAt?: string;
}

export interface GitHubScanJob {
  version: 1;
  jobId: string;
  deliveryId: string;
  installationId: number;
  repository: string;
  headSha: string;
  event: GitHubScanJobEvent;
  baseSha?: string;
  pullRequestNumber?: number;
  createdAt: string;
  attempts: number;
  status: GitHubScanJobStatus;
  leaseUntil?: string;
  /** Unique fencing identity for the current lease. Legacy persisted leases may omit it until reclaim. */
  leaseId?: string;
}

export interface GitHubScanQueueOptions {
  leaseMs?: number;
  now?: () => number;
}

function boundedString(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string") throw new Error(`${label} must be a string.`);
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required.`);
  if (normalized.length > maxLength) throw new Error(`${label} exceeds ${maxLength} characters.`);
  return normalized;
}

function positiveInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) throw new Error(`${label} must be a positive integer.`);
  return value;
}

function repositoryName(value: unknown): string {
  const repository = boundedString(value, "GitHub repository", 255);
  if (!/^[^/\s]+\/[^/\s]+$/.test(repository)) throw new Error("GitHub repository must be in owner/name form.");
  return repository;
}

function sha(value: unknown, label: string): string {
  const normalized = boundedString(value, label, 64).toLowerCase();
  if (!/^[a-f0-9]{40,64}$/.test(normalized)) throw new Error(`${label} must be a hexadecimal commit SHA.`);
  return normalized;
}

function timestamp(value: unknown, label: string): string {
  const normalized = boundedString(value, label, 64);
  if (!Number.isFinite(Date.parse(normalized))) throw new Error(`${label} must be an ISO timestamp.`);
  return normalized;
}

function deliveryId(value: unknown): string {
  const normalized = boundedString(value, "GitHub delivery id", 128);
  if (!/^[A-Za-z0-9._:-]+$/.test(normalized)) throw new Error("GitHub delivery id contains unsupported characters.");
  return normalized;
}

function jobId(value: unknown): string {
  const normalized = boundedString(value, "GitHub scan job id", 64);
  if (!/^[a-f0-9]{32}$/.test(normalized)) throw new Error("GitHub scan job id is invalid.");
  return normalized;
}

function leaseIdentity(value: unknown): string {
  const normalized = boundedString(value, "GitHub scan job lease id", 64).toLowerCase();
  if (!/^[a-f0-9]{32}$/.test(normalized)) throw new Error("GitHub scan job lease id is invalid.");
  return normalized;
}

function leaseMs(value: number | undefined): number {
  const lease = value ?? DEFAULT_LEASE_MS;
  if (!Number.isSafeInteger(lease) || lease < MIN_LEASE_MS || lease > MAX_LEASE_MS) {
    throw new Error(`GitHub scan job lease must be between ${MIN_LEASE_MS} and ${MAX_LEASE_MS} milliseconds.`);
  }
  return lease;
}

function validateJob(value: unknown): GitHubScanJob {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Stored GitHub scan job has an invalid shape.");
  const record = value as Partial<GitHubScanJob>;
  if (record.version !== 1) throw new Error("Stored GitHub scan job has an unsupported version.");
  const event = record.event;
  if (event !== "push" && event !== "pull_request") throw new Error("Stored GitHub scan job has an invalid event type.");
  const status = record.status;
  if (status !== "pending" && status !== "leased" && status !== "failed") throw new Error("Stored GitHub scan job has an invalid status.");
  const attempts = typeof record.attempts === "number" && Number.isSafeInteger(record.attempts) && record.attempts >= 0 && record.attempts <= MAX_ATTEMPTS
    ? record.attempts
    : undefined;
  if (attempts === undefined) throw new Error("Stored GitHub scan job has an invalid attempt count.");
  const pullRequestNumber = record.pullRequestNumber === undefined ? undefined : positiveInteger(record.pullRequestNumber, "GitHub pull request number");
  const baseSha = record.baseSha === undefined ? undefined : sha(record.baseSha, "GitHub base SHA");
  if (event === "pull_request" && (!baseSha || !pullRequestNumber)) throw new Error("Pull request scan jobs require base SHA and pull request number.");
  if (event === "push" && (baseSha || pullRequestNumber)) throw new Error("Push scan jobs must not contain pull request metadata.");
  const leaseUntil = record.leaseUntil === undefined ? undefined : timestamp(record.leaseUntil, "GitHub scan job leaseUntil");
  const leaseId = record.leaseId === undefined ? undefined : leaseIdentity(record.leaseId);
  if (status === "leased" && !leaseUntil) throw new Error("Leased GitHub scan jobs require leaseUntil.");
  if (status !== "leased" && (leaseUntil || leaseId)) throw new Error("Only leased GitHub scan jobs may contain lease metadata.");
  return {
    version: 1,
    jobId: jobId(record.jobId),
    deliveryId: deliveryId(record.deliveryId),
    installationId: positiveInteger(record.installationId, "GitHub installation id"),
    repository: repositoryName(record.repository),
    headSha: sha(record.headSha, "GitHub head SHA"),
    event,
    ...(baseSha ? { baseSha } : {}),
    ...(pullRequestNumber ? { pullRequestNumber } : {}),
    createdAt: timestamp(record.createdAt, "GitHub scan job createdAt"),
    attempts,
    status,
    ...(leaseUntil ? { leaseUntil } : {}),
    ...(leaseId ? { leaseId } : {}),
  };
}

function pathFor(directory: string, id: string): string {
  return join(directory, `${jobId(id)}.json`);
}

async function readJob(path: string): Promise<GitHubScanJob> {
  const metadata = await lstat(path);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size > MAX_JOB_BYTES) {
    throw new Error("Stored GitHub scan job is invalid, symlinked, or oversized.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(path, "utf8"));
  } catch {
    throw new Error("Stored GitHub scan job is invalid JSON.");
  }
  return validateJob(parsed);
}

async function writeJob(directory: string, record: GitHubScanJob): Promise<void> {
  await ensurePrivateDirectory(directory);
  const path = pathFor(directory, record.jobId);
  const tempPath = join(directory, `.job-${record.jobId}-${randomBytes(8).toString("hex")}.tmp`);
  const handle = await open(tempPath, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(record)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await rename(tempPath, path);
  } finally {
    await rm(tempPath, { force: true });
  }
}

function isNotFound(error: unknown): boolean {
  return error instanceof Error && Object.prototype.hasOwnProperty.call(error, "code") && (error as NodeJS.ErrnoException).code === "ENOENT";
}

/** Durable bounded local queue for commit-pinned GitHub App scan work. */
export class FileGitHubScanQueue {
  readonly directory: string;
  readonly leaseMs: number;
  private readonly now: () => number;
  /** Serialize enqueue duplicate/capacity checks within this instance. Cross-process atomicity is not claimed. */
  private enqueueTail: Promise<void> = Promise.resolve();
  /** Serialize claims within this queue instance. Cross-process/multi-host atomicity is intentionally not claimed. */
  private claimTail: Promise<void> = Promise.resolve();

  constructor(directory: string, options: GitHubScanQueueOptions = {}) {
    const normalized = directory.trim();
    if (!normalized) throw new Error("GitHub scan-queue directory is required.");
    this.directory = resolve(normalized);
    this.leaseMs = leaseMs(options.leaseMs);
    this.now = options.now ?? Date.now;
  }

  async enqueue(input: GitHubScanJobInput): Promise<GitHubScanJob> {
    let release!: () => void;
    const previous = this.enqueueTail;
    this.enqueueTail = new Promise<void>((resolveEnqueue) => { release = resolveEnqueue; });
    await previous;
    try {
      return await this.enqueueSerialized(input);
    } finally {
      release();
    }
  }

  private async enqueueSerialized(input: GitHubScanJobInput): Promise<GitHubScanJob> {
    const now = this.now();
    if (!Number.isFinite(now) || now <= 0) throw new Error("GitHub scan-queue clock must be a positive timestamp.");
    const event = input.event;
    if (event !== "push" && event !== "pull_request") throw new Error("GitHub scan job event must be push or pull_request.");
    const candidate = validateJob({
      version: 1,
      jobId: randomBytes(16).toString("hex"),
      deliveryId: input.deliveryId,
      installationId: input.installationId,
      repository: input.repository,
      headSha: input.headSha,
      event,
      ...(input.baseSha ? { baseSha: input.baseSha } : {}),
      ...(input.pullRequestNumber ? { pullRequestNumber: input.pullRequestNumber } : {}),
      createdAt: input.createdAt ?? new Date(now).toISOString(),
      attempts: 0,
      status: "pending",
    });
    const existing = await this.list();
    if (existing.some((job) => job.deliveryId === candidate.deliveryId)) throw new Error("GitHub delivery id is already queued.");
    if (existing.length >= MAX_QUEUE_ENTRIES) throw new Error(`GitHub scan queue reached the ${MAX_QUEUE_ENTRIES}-job limit.`);
    await writeJob(this.directory, candidate);
    return candidate;
  }

  async list(): Promise<GitHubScanJob[]> {
    await ensurePrivateDirectory(this.directory);
    const entries = (await readdir(this.directory, { withFileTypes: true })).filter((entry) => entry.isFile() && /^[a-f0-9]{32}\.json$/.test(entry.name));
    if (entries.length > MAX_QUEUE_ENTRIES) throw new Error(`GitHub scan queue exceeds the ${MAX_QUEUE_ENTRIES}-job limit.`);
    const jobs: GitHubScanJob[] = [];
    for (const entry of entries) {
      const record = await readJob(join(this.directory, entry.name));
      if (`${record.jobId}.json` !== entry.name) throw new Error("Stored GitHub scan job id does not match its filename.");
      jobs.push(record);
    }
    return jobs.sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.jobId.localeCompare(b.jobId));
  }

  async claimNext(): Promise<GitHubScanJob | undefined> {
    let release!: () => void;
    const previous = this.claimTail;
    this.claimTail = new Promise<void>((resolveClaim) => { release = resolveClaim; });
    await previous;
    try {
      return await this.claimNextSerialized();
    } finally {
      release();
    }
  }

  private async claimNextSerialized(): Promise<GitHubScanJob | undefined> {
    while (true) {
      const now = this.now();
      if (!Number.isFinite(now) || now <= 0) throw new Error("GitHub scan-queue clock must be a positive timestamp.");
      const jobs = await this.list();
      const candidate = jobs.find((job) => job.status === "pending" || (job.status === "leased" && Date.parse(job.leaseUntil ?? "") <= now));
      if (!candidate) return undefined;
      if (candidate.attempts >= MAX_ATTEMPTS) {
        const failed = { ...candidate, status: "failed" as const };
        delete failed.leaseUntil;
        delete failed.leaseId;
        await writeJob(this.directory, failed);
        continue;
      }
      const leased: GitHubScanJob = {
        ...candidate,
        attempts: candidate.attempts + 1,
        status: "leased",
        leaseUntil: new Date(now + this.leaseMs).toISOString(),
        leaseId: randomBytes(16).toString("hex"),
      };
      await writeJob(this.directory, leased);
      return leased;
    }
  }

  async assertLease(jobIdValue: string, expectedLeaseId: string): Promise<GitHubScanJob> {
    const current = await this.require(jobIdValue);
    const now = this.now();
    if (!Number.isFinite(now) || now <= 0) throw new Error("GitHub scan-queue clock must be a positive timestamp.");
    const expected = leaseIdentity(expectedLeaseId);
    if (current.status !== "leased" || !current.leaseId || current.leaseId !== expected) {
      throw new Error("GitHub scan job lease is stale or no longer owned by this worker.");
    }
    if (Date.parse(current.leaseUntil ?? "") <= now) {
      throw new Error("GitHub scan job lease has expired.");
    }
    return current;
  }

  async renew(jobIdValue: string, expectedLeaseId: string): Promise<GitHubScanJob> {
    const current = await this.assertLease(jobIdValue, expectedLeaseId);
    const now = this.now();
    const renewed: GitHubScanJob = {
      ...current,
      leaseUntil: new Date(now + this.leaseMs).toISOString(),
    };
    await writeJob(this.directory, renewed);
    return renewed;
  }

  async release(jobIdValue: string, expectedLeaseId: string): Promise<GitHubScanJob> {
    const current = await this.assertLease(jobIdValue, expectedLeaseId);
    const pending: GitHubScanJob = { ...current, status: "pending" };
    delete pending.leaseUntil;
    delete pending.leaseId;
    await writeJob(this.directory, pending);
    return pending;
  }

  async fail(jobIdValue: string, expectedLeaseId: string): Promise<GitHubScanJob> {
    const current = await this.assertLease(jobIdValue, expectedLeaseId);
    const failed: GitHubScanJob = { ...current, status: "failed" };
    delete failed.leaseUntil;
    delete failed.leaseId;
    await writeJob(this.directory, failed);
    return failed;
  }

  async complete(jobIdValue: string, expectedLeaseId: string): Promise<boolean> {
    const current = await this.assertLease(jobIdValue, expectedLeaseId);
    try {
      await stat(pathFor(this.directory, current.jobId));
    } catch (error) {
      if (isNotFound(error)) return false;
      throw error;
    }
    await rm(pathFor(this.directory, current.jobId));
    return true;
  }

  async deleteFailed(jobIdValue: string): Promise<boolean> {
    const current = await this.require(jobIdValue);
    if (current.status !== "failed") throw new Error("Only failed GitHub scan jobs can be deleted by retention.");
    try {
      await rm(pathFor(this.directory, current.jobId));
      return true;
    } catch (error) {
      if (isNotFound(error)) return false;
      throw error;
    }
  }

  private async require(jobIdValue: string): Promise<GitHubScanJob> {
    const id = jobId(jobIdValue);
    await ensurePrivateDirectory(this.directory);
    try {
      const record = await readJob(pathFor(this.directory, id));
      if (record.jobId !== id) throw new Error("Stored GitHub scan job id does not match its filename.");
      return record;
    } catch (error) {
      if (isNotFound(error)) throw new Error("GitHub scan job was not found.");
      throw error;
    }
  }
}
