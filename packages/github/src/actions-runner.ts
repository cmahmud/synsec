import type { SynSecConfig } from "@synsec/config";
import { runScanEngine, type ScanEngineOutcome } from "@synsec/engine";
import type { SynSecReport } from "@synsec/report";
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
}

/**
 * Run the existing repository scanner engine for the current GitHub Actions checkout and publish
 * the completed report as a check run. Pull-request contexts default to changed-file scanning;
 * push/other contexts default to a full repository scan. Optional code-scanning publication uses
 * the same completed report and fixed GitHub host. A local baseline path is size-bounded and
 * commit-bound before it enters the scan engine. No live-target discovery is performed.
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

  const baseline = options.baselinePath
    ? await loadValidatedGitHubBaseline(options.baselinePath, context, {
      expectedCommitSha: options.baselineExpectedCommitSha,
    })
    : options.baseline;
  const changedOnly = options.changedOnly ?? Boolean(context.pullRequestNumber);
  const changedBase = options.changedBase
    ?? (changedOnly && context.baseRef ? `origin/${context.baseRef}` : undefined);
  const scan = options.scan ?? runScanEngine;
  const outcome = await scan({
    rootPath: options.rootPath ?? process.cwd(),
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
  };
}
