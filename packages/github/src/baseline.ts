import { stat } from "node:fs/promises";
import { resolve } from "node:path";
import { readReport, type SynSecReport } from "@synsec/report";
import type { GitHubPullRequestContext } from "./index.js";
import { reportMatchesGitHubCommit } from "./orchestrator.js";

const MAX_GITHUB_BASELINE_BYTES = 20 * 1024 * 1024;

export interface GitHubBaselineLoadOptions {
  expectedCommitSha?: string;
  requireCommitMatch?: boolean;
}

/**
 * Load a bounded local baseline report and, by default, bind it to the PR base commit.
 * This function performs no network retrieval. In PR contexts the event payload's base SHA is
 * required unless the caller supplies an explicit expected commit SHA.
 */
export async function loadValidatedGitHubBaseline(
  path: string,
  context: GitHubPullRequestContext,
  options: GitHubBaselineLoadOptions = {},
): Promise<SynSecReport> {
  const baselinePath = resolve(path);
  const info = await stat(baselinePath);
  if (!info.isFile()) throw new Error(`GitHub baseline path is not a file: ${baselinePath}`);
  if (info.size > MAX_GITHUB_BASELINE_BYTES) {
    throw new Error(`GitHub baseline exceeds ${MAX_GITHUB_BASELINE_BYTES} bytes.`);
  }

  const report = await readReport(baselinePath);
  const requireCommitMatch = options.requireCommitMatch ?? true;
  if (!requireCommitMatch) return report;

  const expected = options.expectedCommitSha?.trim() || context.baseSha?.trim();
  if (!expected) {
    throw new Error("GitHub baseline commit validation requires the pull-request base SHA or an explicit expected commit SHA.");
  }
  const actual = report.target.commitSha?.trim();
  if (!actual) throw new Error("GitHub baseline report does not identify its commit SHA.");
  if (!reportMatchesGitHubCommit(actual, expected)) {
    throw new Error("GitHub baseline report commit does not match the expected base commit.");
  }
  return report;
}
