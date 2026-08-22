import { mkdir, open, readFile, readdir, rename, rm, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { randomBytes } from "node:crypto";

const MAX_RECORD_BYTES = 16 * 1024;
const MAX_LIST_ENTRIES = 10_000;
const MAX_LOGIN_LENGTH = 255;
const MAX_REPOSITORY_COUNT = 10_000;
const MAX_REPOSITORY_LENGTH = 255;

export type GitHubInstallationAccountType = "User" | "Organization";
export type GitHubRepositorySelection = "all" | "selected";

export interface GitHubInstallationRecord {
  version: 1;
  installationId: number;
  accountLogin: string;
  accountType: GitHubInstallationAccountType;
  repositorySelection: GitHubRepositorySelection;
  repositories: string[];
  suspendedAt?: string;
  updatedAt: string;
}

export interface GitHubInstallationRecordInput {
  installationId: number;
  accountLogin: string;
  accountType: GitHubInstallationAccountType;
  repositorySelection: GitHubRepositorySelection;
  repositories?: string[];
  suspendedAt?: string;
  updatedAt?: string;
}

function positiveInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer.`);
  }
  return value;
}

function boundedString(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string") throw new Error(`${label} must be a string.`);
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required.`);
  if (normalized.length > maxLength) throw new Error(`${label} exceeds ${maxLength} characters.`);
  return normalized;
}

function repositoryName(value: unknown): string {
  const repository = boundedString(value, "GitHub repository", MAX_REPOSITORY_LENGTH);
  if (!/^[^/\s]+\/[^/\s]+$/.test(repository)) throw new Error("GitHub repository must be in owner/name form.");
  return repository;
}

function timestamp(value: unknown, label: string): string {
  const normalized = boundedString(value, label, 64);
  if (!Number.isFinite(Date.parse(normalized))) throw new Error(`${label} must be an ISO timestamp.`);
  return normalized;
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
  const repositories = [...new Set(sourceRepositories.map(repositoryName))].sort();
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

function recordPath(directory: string, installationId: number): string {
  return join(directory, `${installationId}.json`);
}

async function readRecord(path: string): Promise<GitHubInstallationRecord> {
  const metadata = await stat(path);
  if (!metadata.isFile() || metadata.size > MAX_RECORD_BYTES) {
    throw new Error("Stored GitHub installation record is invalid or oversized.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(path, "utf8"));
  } catch {
    throw new Error("Stored GitHub installation record is invalid JSON.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Stored GitHub installation record has an invalid shape.");
  }
  const record = parsed as Partial<GitHubInstallationRecord>;
  if (record.version !== 1) throw new Error("Stored GitHub installation record has an unsupported version.");
  return normalize(record as GitHubInstallationRecord);
}

function isNotFound(error: unknown): boolean {
  return error instanceof Error
    && Object.prototype.hasOwnProperty.call(error, "code")
    && (error as NodeJS.ErrnoException).code === "ENOENT";
}

/**
 * Minimal durable GitHub App installation state.
 *
 * Tokens, private keys, webhook secrets, clone URLs, and repository credentials are
 * intentionally not part of this schema. Selected-repository installations persist
 * only validated owner/name identifiers required to decide whether SynSec may scan.
 */
export class FileGitHubInstallationStore {
  readonly directory: string;

  constructor(directory: string) {
    const normalized = directory.trim();
    if (!normalized) throw new Error("GitHub installation-store directory is required.");
    this.directory = resolve(normalized);
  }

  async put(input: GitHubInstallationRecordInput): Promise<GitHubInstallationRecord> {
    const record = normalize(input);
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const path = recordPath(this.directory, record.installationId);
    const tempPath = join(this.directory, `.installation-${record.installationId}-${randomBytes(12).toString("hex")}.tmp`);
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
    return record;
  }

  async get(installationIdValue: number): Promise<GitHubInstallationRecord | undefined> {
    const installationId = positiveInteger(installationIdValue, "GitHub installation id");
    try {
      const record = await readRecord(recordPath(this.directory, installationId));
      if (record.installationId !== installationId) throw new Error("Stored GitHub installation id does not match its filename.");
      return record;
    } catch (error) {
      if (isNotFound(error)) return undefined;
      throw error;
    }
  }

  async remove(installationIdValue: number): Promise<boolean> {
    const installationId = positiveInteger(installationIdValue, "GitHub installation id");
    const path = recordPath(this.directory, installationId);
    try {
      await stat(path);
    } catch (error) {
      if (isNotFound(error)) return false;
      throw error;
    }
    await rm(path);
    return true;
  }

  async list(): Promise<GitHubInstallationRecord[]> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const entries = (await readdir(this.directory, { withFileTypes: true }))
      .filter((entry) => entry.isFile() && /^\d+\.json$/.test(entry.name));
    if (entries.length > MAX_LIST_ENTRIES) throw new Error(`GitHub installation store exceeds the ${MAX_LIST_ENTRIES}-entry limit.`);
    const records: GitHubInstallationRecord[] = [];
    for (const entry of entries) {
      const id = Number(entry.name.slice(0, -5));
      const record = await readRecord(join(this.directory, entry.name));
      if (!Number.isSafeInteger(id) || id <= 0 || record.installationId !== id) {
        throw new Error("Stored GitHub installation id does not match its filename.");
      }
      records.push(record);
    }
    return records.sort((a, b) => a.installationId - b.installationId);
  }

  async isRepositoryAllowed(installationIdValue: number, repositoryValue: string): Promise<boolean> {
    const record = await this.get(installationIdValue);
    if (!record || record.suspendedAt) return false;
    const repository = repositoryName(repositoryValue);
    return record.repositorySelection === "all" || record.repositories.includes(repository);
  }
}
