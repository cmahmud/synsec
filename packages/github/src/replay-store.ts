import { createHash } from "node:crypto";
import { mkdir, open, readFile, readdir, rm, stat } from "node:fs/promises";
import { join, resolve } from "node:path";

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

function recordPath(directory: string, deliveryId: string): string {
  const digest = createHash("sha256").update(deliveryId, "utf8").digest("hex");
  return join(directory, `${digest}.json`);
}

function parseRecord(text: string, expectedDeliveryId: string): ReplayRecord {
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
  if (record.version !== 1 || record.deliveryId !== expectedDeliveryId || typeof record.receivedAt !== "string") {
    throw new Error("Stored GitHub webhook replay record has an invalid shape.");
  }
  const timestamp = Date.parse(record.receivedAt);
  if (!Number.isFinite(timestamp)) throw new Error("Stored GitHub webhook replay timestamp is invalid.");
  return record as ReplayRecord;
}

async function readRecord(path: string, expectedDeliveryId: string): Promise<ReplayRecord> {
  const metadata = await stat(path);
  if (!metadata.isFile() || metadata.size > MAX_RECORD_BYTES) {
    throw new Error("Stored GitHub webhook replay record is invalid or oversized.");
  }
  return parseRecord(await readFile(path, "utf8"), expectedDeliveryId);
}

/**
 * Durable replay protection for GitHub webhook delivery ids.
 *
 * Claims are created with exclusive file creation, so concurrent processes sharing
 * the same store cannot both accept the same delivery. Delivery ids are hashed for
 * filenames and never interpreted as paths. Expired claims may be reclaimed after
 * the configured bounded retention window.
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
    await mkdir(this.directory, { recursive: true, mode: 0o700 });

    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const handle = await open(path, "wx", 0o600);
        try {
          const record: ReplayRecord = { version: 1, deliveryId, receivedAt };
          await handle.writeFile(`${JSON.stringify(record)}\n`, "utf8");
          await handle.sync();
        } finally {
          await handle.close();
        }
        return { accepted: true, deliveryId, receivedAt };
      } catch (error) {
        if (!(error instanceof Error) || !Object.prototype.hasOwnProperty.call(error, "code") || (error as NodeJS.ErrnoException).code !== "EEXIST") {
          throw error;
        }

        const existing = await readRecord(path, deliveryId);
        const existingAt = Date.parse(existing.receivedAt);
        if (now - existingAt < this.retentionMs) {
          return { accepted: false, deliveryId, receivedAt: existing.receivedAt };
        }

        await rm(path, { force: true });
      }
    }

    throw new Error("Unable to claim expired GitHub webhook delivery id safely.");
  }

  async pruneExpired(): Promise<number> {
    const now = this.now();
    if (!Number.isFinite(now) || now <= 0) throw new Error("Webhook replay-store clock must be a positive timestamp.");
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const entries = (await readdir(this.directory, { withFileTypes: true }))
      .filter((entry) => entry.isFile() && /^[a-f0-9]{64}\.json$/.test(entry.name))
      .slice(0, MAX_PRUNE_ENTRIES);

    let removed = 0;
    for (const entry of entries) {
      const path = join(this.directory, entry.name);
      let metadata;
      try {
        metadata = await stat(path);
      } catch {
        continue;
      }
      if (now - metadata.mtimeMs < this.retentionMs) continue;
      await rm(path, { force: true });
      removed += 1;
    }
    return removed;
  }
}
