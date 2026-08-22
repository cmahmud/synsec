import type { SynSecConfig } from "@synsec/config";
import { runScanEngine, type ScanEngineOutcome } from "@synsec/engine";
import {
  runNextGitHubAppScanJob,
  type GitHubAppWorkerAuthorizer,
  type GitHubAppWorkerQueue,
  type GitHubAppWorkerResult,
  type GitHubInstallationTokenPurpose,
} from "./app-worker.js";
import {
  acquireGitHubRepositoryCommit,
  type GitHubRepositoryAcquisitionOptions,
} from "./repository-acquisition.js";
import { buildGitHubCheck, type GitHubCheckThreshold, type GitHubPullRequestContext } from "./index.js";
import { publishGitHubCheck, type GitHubPublisherOptions } from "./publisher.js";
import { publishGitHubSarif } from "./sarif-publisher.js";

export interface ConfiguredGitHubAppWorkerOptions extends GitHubPublisherOptions {
  queue: GitHubAppWorkerQueue;
  installationStore: GitHubAppWorkerAuthorizer;
  config: SynSecConfig;
  getInstallationToken(installationId: number, purpose: GitHubInstallationTokenPurpose): Promise<string>;
  threshold?: GitHubCheckThreshold;
  publishSarif?: boolean;
  toolVersion?: string;
  scan?: typeof runScanEngine;
  acquire?: typeof acquireGitHubRepositoryCommit;
  acquisitionOptions?: GitHubRepositoryAcquisitionOptions;
}

function contextForJob(job: {
  repository: string;
  headSha: string;
  event: "push" | "pull_request";
  pullRequestNumber?: number;
}): GitHubPullRequestContext {
  return {
    repository: job.repository,
    sha: job.headSha,
    ...(job.event === "pull_request" && job.pullRequestNumber
      ? { pullRequestNumber: job.pullRequestNumber }
      : {}),
  };
}

/**
 * Execute one configured hosted-App job through SynSec's existing repository scan engine.
 *
 * Hosted jobs intentionally use a full repository scan at this layer. PR changed-file baselines
 * require separately acquiring the exact base commit and are not approximated from a branch name.
 * Publication uses only the normalized queue repository/head identity and fixed GitHub API hosts.
 */
export async function runConfiguredGitHubAppWorkerOnce(
  options: ConfiguredGitHubAppWorkerOptions,
): Promise<GitHubAppWorkerResult> {
  const scan = options.scan ?? runScanEngine;
  const acquire = options.acquire ?? acquireGitHubRepositoryCommit;

  return runNextGitHubAppScanJob({
    queue: options.queue,
    installationStore: options.installationStore,
    getInstallationToken: options.getInstallationToken,
    acquire,
    acquisitionOptions: options.acquisitionOptions,
    scan: async (_job, workspace) => {
      const outcome: ScanEngineOutcome = await scan({
        rootPath: workspace,
        config: options.config,
        toolVersion: options.toolVersion,
        changedOnly: false,
      });
      return outcome.report;
    },
    publish: async (job, report, installationToken) => {
      const context = contextForJob(job);
      const check = buildGitHubCheck(report, context, {
        threshold: options.threshold,
        onlyNewAnnotations: false,
      });
      await publishGitHubCheck(check, context, installationToken, {
        apiVersion: options.apiVersion,
        userAgent: options.userAgent,
        fetch: options.fetch,
      });
      if (options.publishSarif) {
        await publishGitHubSarif(report, context, installationToken, {
          apiVersion: options.apiVersion,
          userAgent: options.userAgent,
          fetch: options.fetch,
        });
      }
    },
  });
}
