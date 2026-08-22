import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import type { SynSecConfig } from "@synsec/config";
import { runScanEngine, type ScanEngineOutcome } from "@synsec/engine";
import type { SynSecReport } from "@synsec/report";
import { reportMatchesGitHubCommit } from "./orchestrator.js";

const execFileAsync = promisify(execFile);
const COMMIT_SHA = /^[0-9a-f]{7,40}$/i;

export interface GitHubBaseScanOptions {
  toolVersion?: string;
  scan?: typeof runScanEngine;
}

export interface GitHubBaseScanResult {
  report: SynSecReport;
  outcome: ScanEngineOutcome;
}

async function git(rootPath: string, args: string[]): Promise<void> {
  await execFileAsync("git", ["-C", rootPath, ...args], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    windowsHide: true,
  });
}

/**
 * Produce a baseline by scanning one exact commit already present in the local checkout.
 *
 * The commit is checked out into a temporary detached worktree and scanned with changed-file mode
 * disabled. This helper never fetches from a remote, follows a repository-supplied URL, or changes
 * the caller's working tree. The resulting report must identify the requested commit before it is
 * accepted as baseline evidence.
 */
export async function scanGitHubBaseCommit(
  config: SynSecConfig,
  rootPath: string,
  baseSha: string,
  options: GitHubBaseScanOptions = {},
): Promise<GitHubBaseScanResult> {
  const normalizedSha = baseSha.trim();
  if (!COMMIT_SHA.test(normalizedSha)) {
    throw new Error("GitHub base scan requires a valid commit SHA.");
  }

  const repositoryRoot = resolve(rootPath);
  try {
    await git(repositoryRoot, ["cat-file", "-e", `${normalizedSha}^{commit}`]);
  } catch {
    throw new Error(
      "The pull-request base commit is not available in the local checkout. Configure actions/checkout with fetch-depth: 0 (or otherwise fetch the exact base commit) before running SynSec auto-baseline mode.",
    );
  }

  const worktreePath = await mkdtemp(join(tmpdir(), "synsec-github-base-"));
  let worktreeAdded = false;
  try {
    await git(repositoryRoot, ["worktree", "add", "--detach", worktreePath, normalizedSha]);
    worktreeAdded = true;
    const scan = options.scan ?? runScanEngine;
    const outcome = await scan({
      rootPath: worktreePath,
      config,
      toolVersion: options.toolVersion,
      changedOnly: false,
    });
    const actual = outcome.report.target.commitSha?.trim();
    if (!actual || !reportMatchesGitHubCommit(actual, normalizedSha)) {
      throw new Error("Automatic GitHub baseline scan did not produce a report bound to the requested base commit.");
    }
    return { report: outcome.report, outcome };
  } finally {
    if (worktreeAdded) {
      await git(repositoryRoot, ["worktree", "remove", "--force", worktreePath]).catch(() => undefined);
    }
    await rm(worktreePath, { recursive: true, force: true }).catch(() => undefined);
  }
}
