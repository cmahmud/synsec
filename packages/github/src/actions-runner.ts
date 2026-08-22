import type { SynSecConfig } from "@synsec/config";
import { runScanEngine, type ScanEngineOutcome } from "@synsec/engine";
import type { SynSecReport } from "@synsec/report";
import { scanGitHubBaseCommit } from "./base-scan.js";
import { loadValidatedGitHubBaseline } from "./baseline.js";
import { loadGitHubContext, type GitHubPullRequestContext } from "./index.js";
import {
  publishSynSecReportToGitHub,
  type GitHubReportPublicationOptions,
  type GitHubReportPublicationResult,
} from "./orchestrator.js";
import {
  publishGitHubSarif,
  type GitHubSarifPublication,
} from "./sarif-publisher.js";

export interface GitHubActionsRepositoryScanOptions extends GitHubReportPublicationOptions {
  config: SynSecConfig;
  rootPath?: string;
  baseline?: SynSecReport;
  baselinePath?: string;
  baselineExpectedCommitSha?: string;
  autoBaseline?: boolean;
  toolVersion?: string;
  changedOnly?: boolean;
  changedBase?: string;
  publishSarif?: boolean;
  scan?: typeof runScanEngine;
}

export interface GitHubActionsRepositoryScanResult {
  context: GitHubPullRequestContext;
  outcome: ScanEngineOutcome;
  publication: GitHubReportPublicationResult;
  sarifPublication?: GitHubSarifPublication;
  baselineSource?: "provided" | "file" | "base-scan";
}

/**
 * Run the existing repository scanner engine for the current GitHub Actions checkout and publish
 * the completed report as a check run. Pull-request contexts default to changed-file scanning;
 * push/other contexts default to a full repository scan. Optional code-scanning publication uses
 * the same completed report and fixed GitHub host. A local baseline path is size-bounded and
 * commit-bound before it enters the scan engine. Auto-baseline mode scans the exact PR base commit
 * from a temporary local worktree and never performs a remote fetch or live-target discovery.
 */
export async function runGitHubActionsRepositoryScan(
  token: string,
  options: GitHubActionsRepositoryScanOptions,
): Promise<GitHubActionsRepositoryScanResult> {
  const env = options.env ?? process.env;
  const context = await loadGitHubContext(env);
  if (!context) {
    throw new Error("Unable to resolve a valid GitHub repository and commit context for repository scanning.");
  }
  if (options.baseline && options.baselinePath) {
    throw new Error("Provide either an in-memory baseline or baselinePath, not both.");
  }

  const rootPath = options.rootPath ?? process.cwd();
  const scan = options.scan ?? runScanEngine;
  let baseline: SynSecReport | undefined;
  let baselineSource: GitHubActionsRepositoryScanResult["baselineSource"];
  if (options.baselinePath) {
    baseline = await loadValidatedGitHubBaseline(options.baselinePath, context, {
      expectedCommitSha: options.baselineExpectedCommitSha,
    });
    baselineSource = "file";
  } else if (options.baseline) {
    baseline = options.baseline;
    baselineSource = "provided";
  } else if (options.autoBaseline && context.pullRequestNumber) {
    const baseSha = context.baseSha?.trim();
    if (!baseSha) {
      throw new Error("Automatic GitHub baseline generation requires the pull-request base SHA from GITHUB_EVENT_PATH.");
    }
    baseline = (await scanGitHubBaseCommit(options.config, rootPath, baseSha, {
      toolVersion: options.toolVersion,
      scan,
    })).report;
    baselineSource = "base-scan";
  }

  const changedOnly = options.changedOnly ?? Boolean(context.pullRequestNumber);
  const changedBase = options.changedBase
    ?? (changedOnly && context.baseRef ? `origin/${context.baseRef}` : undefined);
  const outcome = await scan({
    rootPath,
    config: options.config,
    baseline,
    toolVersion: options.toolVersion,
    changedOnly,
    changedBase,
  });

  if (!outcome.report.target.commitSha?.trim()) {
    throw new Error("GitHub Actions repository scans must produce a report with a commit SHA before publication.");
  }

  const publication = await publishSynSecReportToGitHub(outcome.report, token, {
    env,
    threshold: options.threshold,
    onlyNewAnnotations: options.onlyNewAnnotations,
    maxAnnotations: options.maxAnnotations,
    apiVersion: options.apiVersion,
    userAgent: options.userAgent,
    fetch: options.fetch,
  });

  const sarifPublication = options.publishSarif
    ? await publishGitHubSarif(outcome.report, context, token, {
      apiVersion: options.apiVersion,
      userAgent: options.userAgent,
      fetch: options.fetch,
    })
    : undefined;

  return {
    context,
    outcome,
    publication,
    ...(sarifPublication ? { sarifPublication } : {}),
    ...(baselineSource ? { baselineSource } : {}),
  };
}
