import type { Severity } from "@synsec/core";
import type { SynSecReport } from "@synsec/report";
import {
  buildGitHubCheck,
  loadGitHubContext,
  type GitHubCheckResult,
  type GitHubPullRequestContext,
} from "./index.js";
import {
  publishGitHubCheck,
  type GitHubCheckPublication,
  type GitHubPublisherOptions,
} from "./publisher.js";

export interface GitHubReportPublicationOptions extends GitHubPublisherOptions {
  env?: NodeJS.ProcessEnv;
  threshold?: Severity;
  onlyNewAnnotations?: boolean;
  maxAnnotations?: number;
}

export interface GitHubReportPublicationResult {
  context: GitHubPullRequestContext;
  check: GitHubCheckResult;
  publication: GitHubCheckPublication;
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
