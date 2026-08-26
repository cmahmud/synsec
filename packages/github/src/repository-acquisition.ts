import { spawn } from "node:child_process";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { markGitHubWorkspaceOwned } from "./workspace-ownership.js";

const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;
const MIN_TIMEOUT_MS = 10_000;
const MAX_TIMEOUT_MS = 30 * 60 * 1000;
const MAX_OUTPUT_BYTES = 1024 * 1024;
const MAX_TOKEN_LENGTH = 4096;
const OWNER_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const REPOSITORY_PATTERN = /^[A-Za-z0-9._-]{1,100}$/;

export interface GitCommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface GitCommandOptions {
  cwd: string;
  env: NodeJS.ProcessEnv;
  timeoutMs: number;
  signal?: AbortSignal;
}

export type GitCommandRunner = (
  args: readonly string[],
  options: GitCommandOptions,
) => Promise<GitCommandResult>;

export interface GitHubRepositoryAcquisitionOptions {
  workspaceRoot?: string;
  timeoutMs?: number;
  signal?: AbortSignal;
  gitRunner?: GitCommandRunner;
  now?: () => number;
}

export interface AcquiredGitHubRepository {
  repository: string;
  commitSha: string;
  workspace: string;
  cleanup(): Promise<void>;
}

export interface AcquiredGitHubScanTarget extends AcquiredGitHubRepository {
  base?: {
    commitSha: string;
    workspace: string;
  };
}

function boundedTimeout(value: number | undefined): number {
  const timeoutMs = value ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < MIN_TIMEOUT_MS || timeoutMs > MAX_TIMEOUT_MS) {
    throw new Error(`GitHub repository acquisition timeout must be between ${MIN_TIMEOUT_MS} and ${MAX_TIMEOUT_MS} milliseconds.`);
  }
  return timeoutMs;
}

function installationToken(value: string): string {
  const token = value.trim();
  if (!token) throw new Error("GitHub installation token is required for repository acquisition.");
  if (token.length > MAX_TOKEN_LENGTH) throw new Error(`GitHub installation token exceeds ${MAX_TOKEN_LENGTH} characters.`);
  if(/[\r\n\0]/.test(token)) throw new Error("GitHub installation token contains unsupported characters.");
  return token;
}

/** Validate one github.com owner/name identity before it is allowed to become a transport URL. */
export function validateGitHubRepositoryIdentity(value: string): string {
  const normalized = value.trim();
  const pieces = normalized.split("/");
  if (pieces.length !== 2) throw new Error("GitHub repository must be in owner/name form.");
  const [owner, repository] = pieces;
  if (!owner || !repository || !OWNER_PATTERN.test(owner) || !REPOSITORY_PATTERN.test(repository)) {
    throw new Error("GitHub repository contains characters that are unsafe for fixed-host acquisition.");
  }
  if (repository === "." || repository === "..") {
    throw new Error("GitHub repository name is invalid.");
  }
  return `${owner}/${repository}`;
}

export function validateGitHubCommitSha(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (!/^[a-f0-9]{40,64}$/.test(normalized)) {
    throw new Error("GitHub commit SHA must be a 40-64 character hexadecimal object id.");
  }
  return normalized;
}

function gitEnvironment(token: string, source: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const auth = Buffer.from(`x-access-token:${token}`, "utf8").toString("base64");
  const env: NodeJS.ProcessEnv = {
    GIT_TERMINAL_PROMPT: "0",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
    GIT_CONFIG_COUNT: "2",
    GIT_CONFIG_KEY_0: "http.https://github.com/.extraheader",
    GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic ${auth}`,
    GIT_CONFIG_KEY_1: "protocol.file.allow",
    GIT_CONFIG_VALUE_1: "never",
    GIT_LFS_SKIP_SMUDGE: "1",
  };

  for (const key of [
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "COMSPEC",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "USERPROFILE",
    "LANG",
    "LC_ALL",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
  ]) {
    const value = source[key];
    if (value !== undefined) env[key] = value;
  }
  for (const [key, value] of Object.entries(source)) {
    if (value !== undefined && key.startsWith("LC_")) env[key] = value;
  }
  return env;
}

async function defaultGitRunner(args: readonly string[], options: GitCommandOptions): Promise<GitCommandResult> {
  if (options.signal?.aborted) throw new Error("GitHub repository acquisition was aborted before git started.");
  return await new Promise<GitCommandResult>((resolvePromise, reject) => {
    const child = spawn("git", [...args], {
      cwd: options.cwd,
      env: options.env,
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;
    let timedOut = false;
    let overflow = false;

    const terminate = (): void => {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    };
    const timeout = setTimeout(() => {
      timedOut = true;
      terminate();
    }, options.timeoutMs);
    const onAbort = (): void => terminate();
    options.signal?.addEventListener("abort", onAbort, { once: true });

    const finish = (callback: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      options.signal?.removeEventListener("abort", onAbort);
      callback();
    };

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdoutBytes += Buffer.byteLength(chunk);
      if (stdoutBytes > MAX_OUTPUT_BYTES) {
        overflow = true;
        terminate();
        return;
      }
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderrBytes += Buffer.byteLength(chunk);
      if (stderrBytes > MAX_OUTPUT_BYTES) {
        overflow = true;
        terminate();
        return;
      }
      stderr += chunk;
    });
    child.once("error", (error) => finish(() => reject(error)));
    child.once("close", (code) => finish(() => {
      if (overflow) return reject(new Error(`git output exceeded the ${MAX_OUTPUT_BYTES}-byte acquisition limit.`));
      if (timedOut) return reject(new Error(`git timed out after ${options.timeoutMs} milliseconds during repository acquisition.`));
      if (options.signal?.aborted) return reject(new Error("GitHub repository acquisition was aborted."));
      resolvePromise({ exitCode: code ?? -1, stdout, stderr });
    }));
  });
}

function commandFailure(stage: string, result: GitCommandResult): Error {
  const detail = result.stderr.replace(/[\r\n]+/g, " ").trim().slice(0, 500);
  return new Error(`GitHub repository acquisition failed during ${stage} (git exit ${result.exitCode})${detail ? `: ${detail}` : "."}`);
}

async function requireGitSuccess(
  runner: GitCommandRunner,
  args: readonly string[],
  options: GitCommandOptions,
  stage: string,
): Promise<GitCommandResult> {
  const result = await runner(args, options);
  if (result.exitCode !== 0) throw commandFailure(stage, result);
  return result;
}

/**
 * Materialize exactly one installation-authorized github.com commit into a fresh detached workspace.
 *
 * The repository identity and commit SHA are validated before URL construction. Git receives the
 * short-lived installation credential only through its child environment, never argv or persisted
 * repository configuration. System/global git configuration and file:// transport are disabled so
 * local URL rewrite rules cannot silently redirect the fixed GitHub transport. Submodules and LFS
 * objects are not initialized. A restrictive ownership marker is created before Git runs so a later
 * maintenance pass can distinguish crashed SynSec workspaces from unrelated directories. The caller
 * owns cleanup after a successful acquisition.
 */
export async function acquireGitHubRepositoryCommit(input: {
  repository: string;
  commitSha: string;
  installationToken: string;
}, options: GitHubRepositoryAcquisitionOptions = {}): Promise<AcquiredGitHubRepository> {
  const repository = validateGitHubRepositoryIdentity(input.repository);
  const commitSha = validateGitHubCommitSha(input.commitSha);
  const token = installationToken(input.installationToken);
  const timeoutMs = boundedTimeout(options.timeoutMs);
  const runner = options.gitRunner ?? defaultGitRunner;
  const root = resolve(options.workspaceRoot?.trim() || tmpdir());
  await mkdir(root, { recursive: true, mode: 0o700 });
  const workspace = await mkdtemp(join(root, "synsec-github-"));
  try {
    await markGitHubWorkspaceOwned(workspace, options.now ?? Date.now);
  } catch (error) {
    await rm(workspace, { recursive: true, force: true });
    throw error;
  }
  const env = gitEnvironment(token);
  const commandOptions: GitCommandOptions = { cwd: workspace, env, timeoutMs, ...(options.signal ? { signal: options.signal } : {}) };
  const remote = `https://github.com/${repository}.git`;

  try {
    await requireGitSuccess(runner, ["init", "--quiet"], commandOptions, "workspace initialization");
    await requireGitSuccess(
      runner,
      ["fetch", "--quiet", "--no-tags", "--depth=1", remote, commitSha],
      commandOptions,
      "exact commit fetch",
    );
    await requireGitSuccess(runner, ["checkout", "--quiet", "--detach", "FETCH_HEAD"], commandOptions, "detached checkout");
    const resolved = await requireGitSuccess(runner, ["rev-parse", "--verify", "HEAD"], commandOptions, "commit verification");
    if (resolved.stdout.trim().toLowerCase() !== commitSha) {
      throw new Error("GitHub repository acquisition produced a commit different from the requested SHA.");
    }
  } catch (error) {
    await rm(workspace, { recursive: true, force: true });
    throw error;
  }

  return {
    repository,
    commitSha,
    workspace,
    cleanup: async () => {
      await rm(workspace, { recursive: true, force: true });
    },
  };
}

/**
 * Acquire the exact head commit and, when supplied, the exact PR base commit as a second isolated
 * workspace. The same short-lived installation credential is used only during this acquisition
 * phase; neither workspace contains persisted Git credentials. Cleanup is all-or-nothing.
 */
export async function acquireGitHubRepositoryScanTarget(input: {
  repository: string;
  commitSha: string;
  baseCommitSha?: string;
  installationToken: string;
}, options: GitHubRepositoryAcquisitionOptions = {}): Promise<AcquiredGitHubScanTarget> {
  const repository = validateGitHubRepositoryIdentity(input.repository);
  const commitSha = validateGitHubCommitSha(input.commitSha);
  const baseCommitSha = input.baseCommitSha === undefined
    ? undefined
    : validateGitHubCommitSha(input.baseCommitSha);

  const head = await acquireGitHubRepositoryCommit({
    repository,
    commitSha,
    installationToken: input.installationToken,
  }, options);

  if (!baseCommitSha) return head;
  if (baseCommitSha === commitSha) {
    return {
      ...head,
      base: { commitSha: baseCommitSha, workspace: head.workspace },
    };
  }

  let base: AcquiredGitHubRepository | undefined;
  try {
    base = await acquireGitHubRepositoryCommit({
      repository,
      commitSha: baseCommitSha,
      installationToken: input.installationToken,
    }, options);
  } catch (error) {
    await head.cleanup();
    throw error;
  }

  return {
    repository,
    commitSha,
    workspace: head.workspace,
    base: { commitSha: base.commitSha, workspace: base.workspace },
    cleanup: async () => {
      await Promise.all([head.cleanup(), base?.cleanup()]);
    },
  };
}
