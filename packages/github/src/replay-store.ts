import { createHash, randomBytes } from "node:crypto";
import { link, open, readFile, readdir, rm, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { ensurePrivateDirectory } from "./private-directory.js";

const DEFAULT_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const MIN_RETENTION_MS = 60 * 60 * 1000;
const MAX_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_DELIVERY_ID_LENGTH = 128;
const MAX_RECORD_BYTES = 1024;
const MAX_PRUNE_ENTRIES = 10_000;

interface ReplayRecord {
  version: 1;
  deliveryId: string;
  receivedAt: string;
}

export interface GitHubWebhookReplayStoreOptions {
  retentionMs?: number;
  now?: () => number;
}

export interface GitHubWebhookDeliveryClaim {
  accepted: boolean;
  deliveryId: string;
  receivedAt: string;
}

function validatedDeliveryId(value: string): string {
  const deliveryId = value.trim();
  if (!deliveryId) throw new Error("GitHub webhook delivery id is required.");
  if (deliveryId.length > MAX_DELIVERY_ID_LENGTH) {
    throw new Error(`GitHub webhook delivery id exceeds ${MAX_DELIVERY_ID_LENGTH} characters.`);
  }
  if (!/^[A-Za-z0-9._:-]+$/.test(deliveryId)) {
    throw new Error("GitHub webhook delivery id contains unsupported characters.");
  }
  return deliveryId;
}

function validatedRetention(value: number | undefined): number {
  const retention = value ?? DEFAULT_RETENTION_MS;
  if (!Number.isSafeInteger(retention) || retention < MIN_RETENTION_MS || retention > MAX_RETENTION_MS) {
    throw new Error(`Webhook replay retention must be an integer between ${MIN_RETENTION_MS} and ${MAX_RETENTION_MS} milliseconds.`);
  }
  return retention;
}

function validatedReceivedAt(value: string): string {
  const normalized = value.trim();
  if (!normalized || !Number.isFinite(Date.parse(normalized))) {
    throw new Error("GitHub webhook replay receivedAt must be an ISO timestamp.");
  }
  return normalized;
}

function recordPath(directory: string, deliveryId: string): string {
  const digest = createHash("sha256").update(deliveryId, "utf8").digest("hex");
  return join(directory, `${digest}.json`);
}

function parseRecord(text: string, expectedDeliveryId?: string): ReplayRecord {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error("Stored GitHub webhook replay record is invalid JSON.");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Stored GitHub webhook replay record is invalid.");
  }
  const record = value as Partial<ReplayRecord>;
  if (record.version !== 1 || typeof record.deliveryId !== "string" || typeof record.receivedAt !== "string") {
    throw new Error("Stored GitHub webhook replay record has an invalid shape.");
  }
  const deliveryId = validatedDeliveryId(record.deliveryId);
  if (expectedDeliveryId !== undefined && deliveryId !== expectedDeliveryId) {
    throw new Error("Stored GitHub webhook replay record has an invalid shape.");
  }
  const receivedAt = validatedReceivedAt(record.receivedAt);
  return { version: 1, deliveryId, receivedAt };
}

async function readRecord(path: string, expectedDeliveryId?: string): Promise<ReplayRecord> {
  const metadata = await stat(path);
  if (!metadata.isFile() || metadata.size > MAX_RECORD_BYTES) {
    throw new Error("Stored GitHub webhook replay record is invalid or oversized.");
  }
  return parseRecord(await readFile(path, "utf8"), expectedDeliveryId);
}

function isAlreadyExists(error: unknown): boolean {
  return error instanceof Error
    && Object.prototype.hasOwnProperty.call(error, "code")
    && (error as NodeJS.ErrnoException).code === "EEXIST";
}

function isNotFound(error: unknown): boolean {
  return error instanceof Error
    && Object.prototype.hasOwnProperty.call(error, "code")
    && (error as NodeJS.ErrnoException).code === "ENOENT";
}

/**
 * Durable replay protection for GitHub webhook delivery ids.
 *
 * Each claim is fully written and fsynced to a private temporary file before an
 * atomic hard-link creates the canonical marker. Concurrent processes sharing the
 * same store therefore cannot both accept a delivery or observe a partial record.
 * Delivery ids are hashed for filenames and never interpreted as paths.
 */
export class FileGitHubWebhookReplayStore {
  readonly directory: string;
  readonly retentionMs: number;
  private readonly now: () => number;

  constructor(directory: string, options: GitHubWebhookReplayStoreOptions = {}) {
    const normalized = directory.trim();
    if (!normalized) throw new Error("Webhook replay-store directory is required.");
    this.directory = resolve(normalized);
    this.retentionMs = validatedRetention(options.retentionMs);
    this.now = options.now ?? Date.now;
  }

  async claim(deliveryIdValue: string): Promise<GitHubWebhookDeliveryClaim> {
    const deliveryId = validatedDeliveryId(deliveryIdValue);
    const now = this.now();
    if (!Number.isFinite(now) || now <= 0) throw new Error("Webhook replay-store clock must be a positive timestamp.");
    const receivedAt = new Date(now).toISOString();
    const path = recordPath(this.directory, deliveryId);
    await ensurePrivateDirectory(this.directory);

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const tempPath = join(this.directory, `.claim-${process.pid}-${randomBytes(12).toString("hex")}.tmp`);
      const handle = await open(tempPath, "wx", 0o600);
      try {
        const record: ReplayRecord = { version: 1, deliveryId, receivedAt };
        await handle.writeFile(`${JSON.stringify(record)}\n`, "utf8");
        await handle.sync();
      } finally {
        await handle.close();
      }

      try {
        await link(tempPath, path);
        return { accepted: true, deliveryId, receivedAt };
      } catch (error) {
        if (!isAlreadyExists(error)) throw error;

        const existing = await readRecord(path, deliveryId);
        const existingAt = Date.parse(existing.receivedAt);
        if (now - existingAt < this.retentionMs) {
          return { accepted: false, deliveryId, receivedAt: existing.receivedAt };
        }

        await rm(path, { force: true });
      } finally {
        await rm(tempPath, { force: true });
      }
    }

    throw new Error("Unable to claim expired GitHub webhook delivery id safely.");
  }

  /**
   * Release only the still-current accepted claim after downstream processing fails.
   * The original receivedAt value binds the release to this claim and an expired claim
   * is never removed, preventing a late worker from deleting a newer reclaimed marker.
   */
  async release(deliveryIdValue: string, receivedAtValue: string): Promise<boolean> {
    const deliveryId = validatedDeliveryId(deliveryIdValue);
    const receivedAt = validatedReceivedAt(receivedAtValue);
    const now = this.now();
    if (!Number.isFinite(now) || now <= 0) throw new Error("Webhook replay-store clock must be a positive timestamp.");
    await ensurePrivateDirectory(this.directory);
    const path = recordPath(this.directory, deliveryId);
    let existing: ReplayRecord;
    try {
      existing = await readRecord(path, deliveryId);
    } catch (error) {
      if (isNotFound(error)) return false;
      throw error;
    }
    if (existing.receivedAt !== receivedAt) return false;
    if (now - Date.parse(existing.receivedAt) >= this.retentionMs) return false;
    await rm(path);
    return true;
  }

  async pruneExpired(): Promise<number> {
    const now = this.now();
    if (!Number.isFinite(now) || now <= 0) throw new Error("Webhook replay-store clock must be a positive timestamp.");
    await ensurePrivateDirectory(this.directory);
    const entries = (await readdir(this.directory, { withFileTypes: true }))
      .filter((entry) => entry.isFile() && /^[a-f0-9]{64}\.json$/.test(entry.name))
      .slice(0, MAX_PRUNE_ENTRIES);

    let removed = 0;
    for (const entry of entries) {
      const path = join(this.directory, entry.name);
      const record = await readRecord(path);
      if (recordPath(this.directory, record.deliveryId) !== path) {
        throw new Error("Stored GitHub webhook replay record does not match its delivery-id filename.");
      }
      if (now - Date.parse(record.receivedAt) < this.retentionMs) continue;
      await rm(path, { force: true });
      removed += 1;
    }
    return removed;
  }
}
