import type { SynSecConfig } from "@synsec/config";
import { runScanEngine, type ScanEngineOutcome } from "@synsec/engine";
import type { SynSecReport } from "@synsec/report";
import { loadGitHubContext, type GitHubPullRequestContext } from "./index.js";
import {
  publishSynSecReportToGitHub,
  type GitHubReportPublicationOptions,
  type GitHubReportPublicationResult,
} from "./orchestrator.js";

export interface GitHubActionsRepositoryScanOptions extends GitHubReportPublicationOptions {
  config: SynSecConfig;
  rootPath?: string;
  baseline?: SynSecReport;
  toolVersion?: string;
  changedOnly?: boolean;
  changedBase?: string;
  scan?: typeof runScanEngine;
}

export interface GitHubActionsRepositoryScanResult {
  context: GitHubPullRequestContext;
  outcome: ScanEngineOutcome;
  publication: GitHubReportPublicationResult;
}

/**
 * Run the existing repository scanner engine for the current GitHub Actions checkout and publish
 * the completed report as a check run. Pull-request contexts default to changed-file scanning;
 * push/other contexts default to a full repository scan. No live-target discovery is performed.
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

  const changedOnly = options.changedOnly ?? Boolean(context.pullRequestNumber);
  const changedBase = options.changedBase
    ?? (changedOnly && context.baseRef ? `origin/${context.baseRef}` : undefined);
  const scan = options.scan ?? runScanEngine;
  const outcome = await scan({
    rootPath: options.rootPath ?? process.cwd(),
    config: options.config,
    baseline: options.baseline,
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

  return { context, outcome, publication };
}
