import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import type { GitHubAppRuntimeCredentialSnapshot } from "./runtime-credentials.js";

const GENERATION_FILE = "generation";
const PRIVATE_KEY_FILE = "private-key.pem";
const WEBHOOK_SECRET_FILE = "webhook-secret";
const PREVIOUS_WEBHOOK_SECRET_FILE = "webhook-secret-previous";
const MAX_GENERATION_BYTES = 512;
const MAX_PRIVATE_KEY_BYTES = 64 * 1024;
const MAX_WEBHOOK_SECRET_BYTES = 4096;

function sanitizedError(message: string): Error {
  return new Error(message);
}

function stripOneTerminalNewline(value: string): string {
  if (value.endsWith("\r\n")) return value.slice(0, -2);
  if (value.endsWith("\n")) return value.slice(0, -1);
  return value;
}

async function readBoundedRegularFile(
  root: string,
  filename: string,
  maximumBytes: number,
  optional = false,
): Promise<string | undefined> {
  const path = join(root, filename);
  let info;
  try {
    info = await lstat(path);
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error
      ? String((error as { code?: unknown }).code ?? "")
      : "";
    if (optional && code === "ENOENT") return undefined;
    throw sanitizedError("GitHub App mounted credential file is unavailable.");
  }
  if (!info.isFile() || info.isSymbolicLink()) {
    throw sanitizedError("GitHub App mounted credential files must be regular non-symlink files.");
  }
  if (info.size < 1 || info.size > maximumBytes) {
    throw sanitizedError("GitHub App mounted credential file violates its byte bound.");
  }
  try {
    return await readFile(path, "utf8");
  } catch {
    throw sanitizedError("GitHub App mounted credential file could not be read.");
  }
}

/**
 * Read one operator-managed GitHub App credential generation from fixed filenames.
 *
 * The directory is an integration boundary for mounted secrets supplied by a supervisor, container
 * orchestrator, CSI driver, tmpfs handoff, or other operator-controlled mechanism. SynSec never
 * writes into this directory. The directory itself and every credential file must be regular and
 * non-symlink shaped; this deliberately prefers a narrow portable contract over following secret
 * manager-specific indirection. Fixed filenames prevent repository or CLI metadata from selecting
 * arbitrary host files, and byte bounds are enforced before reads.
 *
 * Returned credential values are intended to flow immediately into createGitHubAppRuntimeCredentialSource()
 * or its reload() loader. Errors are categorical and never reflect paths or file contents.
 */
export async function loadMountedGitHubAppRuntimeCredentialSnapshot(
  directoryValue: string,
): Promise<GitHubAppRuntimeCredentialSnapshot> {
  if (typeof directoryValue !== "string" || !isAbsolute(directoryValue) || directoryValue.includes("\0")) {
    throw sanitizedError("GitHub App mounted credential directory must be an absolute path.");
  }
  const directory = resolve(directoryValue);
  let directoryInfo;
  try {
    directoryInfo = await lstat(directory);
  } catch {
    throw sanitizedError("GitHub App mounted credential directory is unavailable.");
  }
  if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) {
    throw sanitizedError("GitHub App mounted credential directory must be a non-symlink directory.");
  }

  const [generationRaw, privateKey, activeSecretRaw, previousSecretRaw] = await Promise.all([
    readBoundedRegularFile(directory, GENERATION_FILE, MAX_GENERATION_BYTES),
    readBoundedRegularFile(directory, PRIVATE_KEY_FILE, MAX_PRIVATE_KEY_BYTES),
    readBoundedRegularFile(directory, WEBHOOK_SECRET_FILE, MAX_WEBHOOK_SECRET_BYTES),
    readBoundedRegularFile(directory, PREVIOUS_WEBHOOK_SECRET_FILE, MAX_WEBHOOK_SECRET_BYTES, true),
  ]);

  const generation = stripOneTerminalNewline(generationRaw ?? "").trim();
  const activeSecret = stripOneTerminalNewline(activeSecretRaw ?? "");
  const previousSecret = previousSecretRaw === undefined ? undefined : stripOneTerminalNewline(previousSecretRaw);
  if (!generation || !privateKey || !activeSecret) {
    throw sanitizedError("GitHub App mounted credential snapshot is incomplete.");
  }

  return {
    generation,
    privateKey,
    webhookSecret: previousSecret === undefined ? activeSecret : [activeSecret, previousSecret] as const,
  };
}
