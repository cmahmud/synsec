import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import type { ApprovedRemediationExecution, RemediationChange } from "@synsec/workflows/remediation";
import { validateGitHubCommitSha, validateGitHubRepositoryIdentity } from "./repository-acquisition.js";

const MAX_OUTPUT_BYTES = 1024 * 1024;
const MAX_TOKEN_LENGTH = 4096;
const MAX_BRANCH_LENGTH = 200;
const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;
const MIN_TIMEOUT_MS = 10_000;
const MAX_TIMEOUT_MS = 30 * 60 * 1000;

export interface RemediationGitResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface RemediationGitOptions {
  cwd: string;
  env: NodeJS.ProcessEnv;
  timeoutMs: number;
}

export type RemediationGitRunner = (
  args: readonly string[],
  options: RemediationGitOptions,
) => Promise<RemediationGitResult>;

export interface GitHubRemediationWriterOptions {
  fetch?: typeof fetch;
  gitRunner?: RemediationGitRunner;
  timeoutMs?: number;
  apiVersion?: string;
  userAgent?: string;
  tempRoot?: string;
}

export interface GitHubRemediationWriteInput {
  repository: string;
  baseBranch: string;
  workspace: string;
  installationToken: string;
  execution: ApprovedRemediationExecution;
}

export interface GitHubRemediationPullRequestResult {
  repository: string;
  proposalId: string;
  branch: string;
  commitSha: string;
  pullRequestNumber: number;
  pullRequestUrl: string;
}

function boundedTimeout(value: number | undefined): number {
  const timeoutMs = value ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < MIN_TIMEOUT_MS || timeoutMs > MAX_TIMEOUT_MS) {
    throw new Error(`GitHub remediation timeout must be between ${MIN_TIMEOUT_MS} and ${MAX_TIMEOUT_MS} milliseconds.`);
  }
  return timeoutMs;
}

function installationToken(value: string): string {
  const token = value.trim();
  if (!token) throw new Error("GitHub installation token is required for remediation publication.");
  if (token.length > MAX_TOKEN_LENGTH) throw new Error(`GitHub installation token exceeds ${MAX_TOKEN_LENGTH} characters.`);
  if (/[\r\n\0]/.test(token)) throw new Error("GitHub installation token contains unsupported characters.");
  return token;
}

function branchName(value: string): string {
  const branch = value.trim();
  if (
    !branch ||
    branch.length > MAX_BRANCH_LENGTH ||
    !/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(branch) ||
    branch.includes("..") ||
    branch.includes("//") ||
    branch.includes("@{") ||
    branch.endsWith("/") ||
    branch.endsWith(".") ||
    branch.endsWith(".lock")
  ) {
    throw new Error("GitHub remediation base branch is invalid.");
  }
  return branch;
}

function remediationBranch(proposalId: string): string {
  if (!/^[a-f0-9]{64}$/.test(proposalId)) throw new Error("Remediation proposal id is invalid.");
  return `synsec/remediation/${proposalId.slice(0, 20)}`;
}

function gitEnvironment(token: string): NodeJS.ProcessEnv {
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
  for (const key of ["PATH", "PATHEXT", "SYSTEMROOT", "COMSPEC", "WINDIR", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR"]) {
    const value = process.env[key];
    if (value !== undefined) env[key] = value;
  }
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && key.startsWith("LC_")) env[key] = value;
  }
  return env;
}

async function defaultGitRunner(args: readonly string[], options: RemediationGitOptions): Promise<RemediationGitResult> {
  return await new Promise((resolvePromise, reject) => {
    const child = spawn("git", [...args], {
      cwd: options.cwd,
      env: options.env,
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let outputBytes = 0;
    let overflow = false;
    let timedOut = false;
    let settled = false;
    const terminate = (): void => {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    };
    const timeout = setTimeout(() => {
      timedOut = true;
      terminate();
    }, options.timeoutMs);
    const finish = (callback: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      callback();
    };
    const collect = (chunk: string, target: "stdout" | "stderr"): void => {
      outputBytes += Buffer.byteLength(chunk);
      if (outputBytes > MAX_OUTPUT_BYTES) {
        overflow = true;
        terminate();
        return;
      }
      if (target === "stdout") stdout += chunk;
      else stderr += chunk;
    };
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => collect(chunk, "stdout"));
    child.stderr.on("data", (chunk: string) => collect(chunk, "stderr"));
    child.once("error", (error) => finish(() => reject(error)));
    child.once("close", (code) => finish(() => {
      if (overflow) return reject(new Error(`git output exceeded the ${MAX_OUTPUT_BYTES}-byte remediation limit.`));
      if (timedOut) return reject(new Error(`git timed out after ${options.timeoutMs} milliseconds during remediation.`));
      resolvePromise({ exitCode: code ?? -1, stdout, stderr });
    }));
  });
}

function failure(stage: string, result: RemediationGitResult): Error {
  const detail = result.stderr.replace(/[\r\n]+/g, " ").trim().slice(0, 500);
  return new Error(`GitHub remediation failed during ${stage} (git exit ${result.exitCode})${detail ? `: ${detail}` : "."}`);
}

async function requireGit(
  runner: RemediationGitRunner,
  args: readonly string[],
  options: RemediationGitOptions,
  stage: string,
): Promise<RemediationGitResult> {
  const result = await runner(args, options);
  if (result.exitCode !== 0) throw failure(stage, result);
  return result;
}

function parseRemoteRef(result: RemediationGitResult, expectedRef: string): string | undefined {
  if (result.exitCode === 2 && !result.stdout.trim()) return undefined;
  if (result.exitCode !== 0) throw failure("remote ref lookup", result);
  const lines = result.stdout.trim().split(/\r?\n/).filter(Boolean);
  if (lines.length !== 1) throw new Error("GitHub remediation remote ref lookup returned ambiguous output.");
  const [sha, ref, ...extra] = lines[0].split(/\s+/);
  if (!sha || ref !== expectedRef || extra.length > 0) throw new Error("GitHub remediation remote ref lookup returned malformed output.");
  return validateGitHubCommitSha(sha);
}

function expectedStatus(change: RemediationChange): "A" | "M" {
  return change.operation === "create" ? "A" : "M";
}

function assertStagedChanges(output: string, changes: readonly RemediationChange[]): void {
  const actual = new Map<string, string>();
  for (const line of output.split(/\r?\n/).filter(Boolean)) {
    const match = /^([AM])\t(.+)$/.exec(line);
    if (!match) throw new Error("GitHub remediation staged an unsupported change type.");
    const [, status, path] = match;
    if (actual.has(path)) throw new Error("GitHub remediation staged a duplicate path.");
    actual.set(path, status);
  }
  if (actual.size !== changes.length) throw new Error("GitHub remediation staged paths differ from the approved proposal.");
  for (const change of changes) {
    if (actual.get(change.path) !== expectedStatus(change)) {
      throw new Error("GitHub remediation staged paths or operations differ from the approved proposal.");
    }
  }
}

function safeApiVersion(value: string | undefined): string {
  const version = value?.trim() || "2022-11-28";
  if (!/^\d{4}-\d{2}-\d{2}$/.test(version)) throw new Error("GitHub API version is invalid.");
  return version;
}

function safeUserAgent(value: string | undefined): string {
  const userAgent = value?.trim() || "synsec-remediation/0.2";
  if (!userAgent || userAgent.length > 200 || /[\r\n\0]/.test(userAgent)) throw new Error("GitHub user agent is invalid.");
  return userAgent;
}

async function createPullRequest(input: {
  fetchImpl: typeof fetch;
  repository: string;
  token: string;
  branch: string;
  baseBranch: string;
  execution: ApprovedRemediationExecution;
  apiVersion: string;
  userAgent: string;
}): Promise<{ number: number; htmlUrl: string }> {
  const response = await input.fetchImpl(`https://api.github.com/repos/${input.repository}/pulls`, {
    method: "POST",
    redirect: "error",
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${input.token}`,
      "x-github-api-version": input.apiVersion,
      "user-agent": input.userAgent,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      title: `SynSec remediation ${input.execution.proposal.proposalId.slice(0, 12)}`,
      head: input.branch,
      base: input.baseBranch,
      body: [
        input.execution.proposal.summary,
        "",
        `Approved SynSec proposal: ${input.execution.proposal.proposalId}`,
        `Findings addressed: ${input.execution.proposal.findingIds.length}`,
        "",
        "This pull request was created only after explicit approval of the exact patch set and commit provenance.",
      ].join("\n"),
    }),
  });
  if (!response.ok) throw new Error(`GitHub remediation pull-request creation failed with HTTP ${response.status}.`);
  const payload = await response.json() as { number?: unknown; html_url?: unknown };
  if (typeof payload.number !== "number" || !Number.isSafeInteger(payload.number) || payload.number <= 0) {
    throw new Error("GitHub remediation pull-request response did not contain a valid number.");
  }
  if (typeof payload.html_url !== "string" || !/^https:\/\/github\.com\//.test(payload.html_url)) {
    throw new Error("GitHub remediation pull-request response did not contain a fixed-host GitHub URL.");
  }
  return { number: payload.number, htmlUrl: payload.html_url };
}

/**
 * Apply one explicitly approved remediation proposal to an already acquired exact worktree, push a
 * deterministic non-force branch to github.com, and open a pull request through api.github.com.
 *
 * The writer rechecks the remote base ref before any mutation, verifies the local worktree commit,
 * checks the patch before applying it, and requires Git's staged path/status set to exactly equal
 * the approved proposal. Installation credentials are used only for GitHub transport and never
 * written into the repository or passed to scanners.
 */
export async function createApprovedGitHubRemediationPullRequest(
  input: GitHubRemediationWriteInput,
  options: GitHubRemediationWriterOptions = {},
): Promise<GitHubRemediationPullRequestResult> {
  const repository = validateGitHubRepositoryIdentity(input.repository);
  const baseBranch = branchName(input.baseBranch);
  const targetCommitSha = validateGitHubCommitSha(input.execution.targetCommitSha);
  if (input.execution.proposal.targetCommitSha !== targetCommitSha) {
    throw new Error("Approved remediation execution target does not match its proposal.");
  }
  if (input.execution.approval.proposalId !== input.execution.proposal.proposalId) {
    throw new Error("Approved remediation execution contains mismatched approval metadata.");
  }
  const token = installationToken(input.installationToken);
  const timeoutMs = boundedTimeout(options.timeoutMs);
  const runner = options.gitRunner ?? defaultGitRunner;
  const workspace = resolve(input.workspace);
  const remote = `https://github.com/${repository}.git`;
  const branch = remediationBranch(input.execution.proposal.proposalId);
  const env = gitEnvironment(token);
  const gitOptions: RemediationGitOptions = { cwd: workspace, env, timeoutMs };

  const localHead = (await requireGit(runner, ["rev-parse", "--verify", "HEAD"], gitOptions, "local commit verification")).stdout.trim().toLowerCase();
  if (validateGitHubCommitSha(localHead) !== targetCommitSha) {
    throw new Error("GitHub remediation workspace is not at the approved target commit.");
  }

  const baseRef = `refs/heads/${baseBranch}`;
  const baseLookup = await runner(["ls-remote", "--refs", remote, baseRef], gitOptions);
  const remoteBaseSha = parseRemoteRef(baseLookup, baseRef);
  if (!remoteBaseSha || remoteBaseSha !== targetCommitSha) {
    throw new Error("GitHub remediation base branch moved after approval; regenerate and reapprove the patch set.");
  }

  const patchDirectory = await mkdtemp(join(resolve(options.tempRoot?.trim() || tmpdir()), "synsec-remediation-"));
  const patchPath = join(patchDirectory, "approved.patch");
  try {
    await writeFile(patchPath, input.execution.proposal.changes.map((change) => change.patch).join("\n"), { encoding: "utf8", mode: 0o600 });
    await requireGit(runner, ["apply", "--cached", "--check", "--whitespace=nowarn", patchPath], gitOptions, "approved patch check");
    await requireGit(runner, ["apply", "--cached", "--whitespace=nowarn", patchPath], gitOptions, "approved patch application");
    const staged = await requireGit(runner, ["diff", "--cached", "--name-status", "--no-renames"], gitOptions, "staged change verification");
    assertStagedChanges(staged.stdout, input.execution.proposal.changes);

    const commitEnv: NodeJS.ProcessEnv = {
      ...env,
      GIT_AUTHOR_NAME: "SynSec",
      GIT_AUTHOR_EMAIL: "synsec@users.noreply.github.com",
      GIT_COMMITTER_NAME: "SynSec",
      GIT_COMMITTER_EMAIL: "synsec@users.noreply.github.com",
      GIT_AUTHOR_DATE: input.execution.approval.approvedAt,
      GIT_COMMITTER_DATE: input.execution.approval.approvedAt,
    };
    const commitOptions: RemediationGitOptions = { ...gitOptions, env: commitEnv };
    await requireGit(
      runner,
      ["commit", "--no-gpg-sign", "--no-verify", "-m", `SynSec remediation ${input.execution.proposal.proposalId.slice(0, 12)}`],
      commitOptions,
      "remediation commit",
    );
    const commitSha = validateGitHubCommitSha((await requireGit(runner, ["rev-parse", "--verify", "HEAD"], gitOptions, "remediation commit verification")).stdout.trim());

    const remediationRef = `refs/heads/${branch}`;
    const existing = parseRemoteRef(await runner(["ls-remote", "--refs", remote, remediationRef], gitOptions), remediationRef);
    if (existing && existing !== commitSha) {
      throw new Error("GitHub remediation branch already exists with different contents.");
    }
    if (!existing) {
      await requireGit(runner, ["push", remote, `HEAD:${remediationRef}`], gitOptions, "non-force remediation branch push");
    }

    const pullRequest = await createPullRequest({
      fetchImpl: options.fetch ?? fetch,
      repository,
      token,
      branch,
      baseBranch,
      execution: input.execution,
      apiVersion: safeApiVersion(options.apiVersion),
      userAgent: safeUserAgent(options.userAgent),
    });
    return {
      repository,
      proposalId: input.execution.proposal.proposalId,
      branch,
      commitSha,
      pullRequestNumber: pullRequest.number,
      pullRequestUrl: pullRequest.htmlUrl,
    };
  } finally {
    await rm(patchDirectory, { recursive: true, force: true });
  }
}
