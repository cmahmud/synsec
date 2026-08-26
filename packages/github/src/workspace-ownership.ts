import { randomBytes } from "node:crypto";
import { lstat, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";

const MARKER_FILE = ".synsec-workspace.json";
const WORKSPACE_PREFIX = "synsec-github-";
const MARKER_VERSION = 1;
const MIN_RETENTION_MS = 60 * 60 * 1000;
const MAX_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const DEFAULT_RETENTION_MS = 24 * 60 * 60 * 1000;
const DEFAULT_MAX_DELETES = 32;
const MAX_DELETES = 256;
const MAX_MARKER_BYTES = 4096;

export interface GitHubWorkspaceOwnershipMarker {
  version: 1;
  workspaceId: string;
  createdAt: string;
}

export interface GitHubWorkspaceReconciliationOptions {
  retentionMs?: number;
  maxDeletes?: number;
  deleteOwned?: boolean;
  now?: () => number;
}

export interface GitHubWorkspaceReconciliationResult {
  inspected: number;
  owned: number;
  stale: number;
  deleted: number;
  skipped: number;
}

function boundedRetention(value: number | undefined): number {
  const retentionMs = value ?? DEFAULT_RETENTION_MS;
  if (!Number.isSafeInteger(retentionMs) || retentionMs < MIN_RETENTION_MS || retentionMs > MAX_RETENTION_MS) {
    throw new Error(`GitHub workspace retention must be between ${MIN_RETENTION_MS} and ${MAX_RETENTION_MS} milliseconds.`);
  }
  return retentionMs;
}

function boundedMaxDeletes(value: number | undefined): number {
  const maxDeletes = value ?? DEFAULT_MAX_DELETES;
  if (!Number.isSafeInteger(maxDeletes) || maxDeletes < 1 || maxDeletes > MAX_DELETES) {
    throw new Error(`GitHub workspace reconciliation maxDeletes must be between 1 and ${MAX_DELETES}.`);
  }
  return maxDeletes;
}

function parseMarker(raw: string): GitHubWorkspaceOwnershipMarker {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("GitHub workspace ownership marker is not valid JSON.");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("GitHub workspace ownership marker has an invalid shape.");
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.join(",") !== "createdAt,version,workspaceId") {
    throw new Error("GitHub workspace ownership marker contains unsupported fields.");
  }
  if (record.version !== MARKER_VERSION) throw new Error("GitHub workspace ownership marker version is unsupported.");
  if (typeof record.workspaceId !== "string" || !/^[a-f0-9]{32}$/.test(record.workspaceId)) {
    throw new Error("GitHub workspace ownership marker id is invalid.");
  }
  if (typeof record.createdAt !== "string") throw new Error("GitHub workspace ownership marker timestamp is invalid.");
  const createdAt = Date.parse(record.createdAt);
  if (!Number.isFinite(createdAt)) throw new Error("GitHub workspace ownership marker timestamp is invalid.");
  return { version: 1, workspaceId: record.workspaceId, createdAt: record.createdAt };
}

export async function markGitHubWorkspaceOwned(workspace: string, now: () => number = Date.now): Promise<GitHubWorkspaceOwnershipMarker> {
  const created = now();
  if (!Number.isFinite(created) || created <= 0) throw new Error("GitHub workspace ownership clock must be a positive timestamp.");
  const marker: GitHubWorkspaceOwnershipMarker = {
    version: 1,
    workspaceId: randomBytes(16).toString("hex"),
    createdAt: new Date(created).toISOString(),
  };
  await writeFile(join(resolve(workspace), MARKER_FILE), `${JSON.stringify(marker)}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  return marker;
}

async function readOwnedMarker(workspace: string): Promise<GitHubWorkspaceOwnershipMarker | undefined> {
  const markerPath = join(workspace, MARKER_FILE);
  let metadata;
  try {
    metadata = await lstat(markerPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size <= 0 || metadata.size > MAX_MARKER_BYTES) return undefined;
  const raw = await readFile(markerPath, "utf8");
  return parseMarker(raw);
}

/**
 * Inspect or remove stale SynSec-owned acquisition workspaces under one configured root.
 *
 * Observation is the default. Deletion requires `deleteOwned:true`, a valid restrictive ownership
 * marker, the expected generated directory prefix, an age beyond the bounded retention window, and
 * a bounded deletion batch. Unrelated directories, symlinks, missing markers, and malformed marker
 * shapes are never removed. A malformed marker is counted as skipped rather than interpreted as
 * evidence of ownership.
 */
export async function reconcileGitHubOwnedWorkspaces(
  workspaceRoot: string,
  options: GitHubWorkspaceReconciliationOptions = {},
): Promise<GitHubWorkspaceReconciliationResult> {
  const root = resolve(workspaceRoot);
  const retentionMs = boundedRetention(options.retentionMs);
  const maxDeletes = boundedMaxDeletes(options.maxDeletes);
  const now = options.now ?? Date.now;
  const currentTime = now();
  if (!Number.isFinite(currentTime) || currentTime <= 0) throw new Error("GitHub workspace reconciliation clock must be a positive timestamp.");

  const result: GitHubWorkspaceReconciliationResult = { inspected: 0, owned: 0, stale: 0, deleted: 0, skipped: 0 };
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (!entry.name.startsWith(WORKSPACE_PREFIX)) continue;
    result.inspected += 1;
    if (!entry.isDirectory() || entry.isSymbolicLink()) {
      result.skipped += 1;
      continue;
    }
    const workspace = join(root, entry.name);
    if (basename(workspace) !== entry.name) {
      result.skipped += 1;
      continue;
    }
    let marker: GitHubWorkspaceOwnershipMarker | undefined;
    try {
      marker = await readOwnedMarker(workspace);
    } catch {
      result.skipped += 1;
      continue;
    }
    if (!marker) {
      result.skipped += 1;
      continue;
    }
    result.owned += 1;
    const age = currentTime - Date.parse(marker.createdAt);
    if (!Number.isFinite(age) || age < retentionMs) continue;
    result.stale += 1;
    if (!options.deleteOwned || result.deleted >= maxDeletes) continue;

    // Re-read immediately before deletion so replacement/tampering after discovery fails closed.
    let current: GitHubWorkspaceOwnershipMarker | undefined;
    try {
      current = await readOwnedMarker(workspace);
    } catch {
      result.skipped += 1;
      continue;
    }
    if (!current || current.workspaceId !== marker.workspaceId || current.createdAt !== marker.createdAt) {
      result.skipped += 1;
      continue;
    }
    await rm(workspace, { recursive: true, force: false });
    result.deleted += 1;
  }
  return result;
}
