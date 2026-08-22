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
  acquireGitHubRepositoryScanTarget,
  type GitHubRepositoryAcquisitionOptions,
} from "./repository-acquisition.js";
import { deriveExactChangedFiles, type ExactTreeDiffPlan } from "./exact-tree-diff.js";
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
  acquire?: typeof acquireGitHubRepositoryScanTarget;
  deriveChangedFiles?: typeof deriveExactChangedFiles;
  acquisitionOptions?: GitHubRepositoryAcquisitionOptions;
}

function contextForJob(job: {
  repository: string;
  headSha: string;
  event: "push" | "pull_request";
  baseSha?: string;
  pullRequestNumber?: number;
}): GitHubPullRequestContext {
  return {
    repository: job.repository,
    sha: job.headSha,
    ...(job.event === "pull_request" && job.baseSha ? { baseSha: job.baseSha } : {}),
    ...(job.event === "pull_request" && job.pullRequestNumber
      ? { pullRequestNumber: job.pullRequestNumber }
      : {}),
  };
}

function requireCommit(reportCommitSha: string | undefined, expectedSha: string, label: string): void {
  const actual = reportCommitSha?.trim().toLowerCase();
  if (!actual || actual !== expectedSha.toLowerCase()) {
    throw new Error(`${label} report commit does not match the queued GitHub commit SHA.`);
  }
}

function useTargetedHeadScan(plan: ExactTreeDiffPlan | undefined, publishSarif: boolean | undefined): boolean {
  // A partial SARIF analysis can make untouched alerts appear absent to code scanning, so hosted
  // workers keep SARIF-enabled jobs repository-wide until a merge-safe partial publication contract
  // is implemented. Empty diffs likewise stay full to avoid adapter-specific empty-scope semantics.
  return Boolean(
    plan
      && plan.mode === "changed-files"
      && plan.changedFiles.length > 0
      && !publishSarif,
  );
}

/**
 * Execute one configured hosted-App job through SynSec's existing repository scan engine.
 *
 * Push jobs scan the exact acquired head commit. Pull-request jobs additionally acquire and scan
 * the exact queued base commit, bind that report to baseSha, and use it as the deterministic
 * baseline for the exact head scan. When the two acquired Git trees can be compared safely, the
 * head scan may use only exact changed paths. Tree-diff ambiguity, deletions, excessive scope, and
 * SARIF publication fail back to a full repository scan rather than weakening coverage. No branch
 * names, unbounded history fetches, or remote target expansion are used for scope derivation.
 */
export async function runConfiguredGitHubAppWorkerOnce(
  options: ConfiguredGitHubAppWorkerOptions,
): Promise<GitHubAppWorkerResult> {
  const scan = options.scan ?? runScanEngine;
  const acquire = options.acquire ?? acquireGitHubRepositoryScanTarget;
  const deriveChangedFiles = options.deriveChangedFiles ?? deriveExactChangedFiles;

  return runNextGitHubAppScanJob({
    queue: options.queue,
    installationStore: options.installationStore,
    getInstallationToken: options.getInstallationToken,
    acquire,
    acquisitionOptions: options.acquisitionOptions,
    scan: async (job, workspace, baseWorkspace) => {
      let baseline: ScanEngineOutcome["report"] | undefined;
      let exactDiff: ExactTreeDiffPlan | undefined;
      if (job.event === "pull_request") {
        if (!job.baseSha || !baseWorkspace) {
          throw new Error("Hosted pull-request scan requires the exact acquired base workspace.");
        }
        const baseOutcome: ScanEngineOutcome = await scan({
          rootPath: baseWorkspace,
          config: options.config,
          toolVersion: options.toolVersion,
          changedOnly: false,
        });
        requireCommit(baseOutcome.report.target.commitSha, job.baseSha, "GitHub App baseline");
        baseline = baseOutcome.report;
        exactDiff = await deriveChangedFiles(baseWorkspace, workspace);
      }

      const targeted = useTargetedHeadScan(exactDiff, options.publishSarif);
      const outcome: ScanEngineOutcome = await scan({
        rootPath: workspace,
        config: options.config,
        toolVersion: options.toolVersion,
        ...(baseline ? { baseline } : {}),
        changedOnly: targeted,
        ...(targeted && job.baseSha && exactDiff
          ? { changedBase: job.baseSha, changedFiles: exactDiff.changedFiles }
          : {}),
      });
      requireCommit(outcome.report.target.commitSha, job.headSha, "GitHub App head");
      return outcome.report;
    },
    publish: async (job, report, installationToken) => {
      const context = contextForJob(job);
      const check = buildGitHubCheck(report, context, {
        threshold: options.threshold,
        onlyNewAnnotations: Boolean(report.baseline),
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
