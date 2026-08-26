import type { SynSecReport } from "@synsec/report";
import {
  buildGitHubCheck,
  loadGitHubContext,
  type GitHubCheckResult,
  type GitHubCheckThreshold,
  type GitHubPullRequestContext,
} from "./index.js";
import {
  publishGitHubCheck,
  type GitHubCheckPublication,
  type GitHubPublisherOptions,
} from "./publisher.js";

export interface GitHubReportPublicationOptions extends GitHubPublisherOptions {
  env?: NodeJS.ProcessEnv;
  threshold?: GitHubCheckThreshold;
  onlyNewAnnotations?: boolean;
  maxAnnotations?: number;
}

export interface GitHubReportPublicationResult {
  context: GitHubPullRequestContext;
  check: GitHubCheckResult;
  publication: GitHubCheckPublication;
}

export function reportMatchesGitHubCommit(reportSha: string, contextSha: string): boolean {
  const report = reportSha.trim().toLowerCase();
  const context = contextSha.trim().toLowerCase();
  if (!report || !context) return false;
  if (report === context) return true;

  const hexSha = /^[0-9a-f]+$/;
  if (!hexSha.test(report) || !hexSha.test(context) || Math.min(report.length, context.length) < 7) return false;
  return report.startsWith(context) || context.startsWith(report);
}

/**
 * Convert a completed SynSec report into a GitHub check and publish it to the commit represented
 * by the bounded local Actions context. This function never performs scanning, target discovery,
 * repository mutation, or external assessment; it only transports an already-produced report.
 */
export async function publishSynSecReportToGitHub(
  report: SynSecReport,
  token: string,
  options: GitHubReportPublicationOptions = {},
): Promise<GitHubReportPublicationResult> {
  const context = await loadGitHubContext(options.env ?? process.env);
  if (!context) {
    throw new Error("Unable to resolve a valid GitHub repository and commit context for check publication.");
  }

  const reportCommitSha = report.target.commitSha?.trim();
  if (reportCommitSha && !reportMatchesGitHubCommit(reportCommitSha, context.sha)) {
    throw new Error("SynSec report commit does not match the GitHub commit selected for publication.");
  }

  const check = buildGitHubCheck(report, context, {
    threshold: options.threshold,
    onlyNewAnnotations: options.onlyNewAnnotations,
    maxAnnotations: options.maxAnnotations,
  });

  const publication = await publishGitHubCheck(check, context, token, {
    apiVersion: options.apiVersion,
    userAgent: options.userAgent,
    fetch: options.fetch,
  });

  return { context, check, publication };
}
