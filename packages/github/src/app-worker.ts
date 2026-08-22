import type { SynSecReport } from "@synsec/report";
import {
  acquireGitHubRepositoryCommit,
  type AcquiredGitHubRepository,
  type GitHubRepositoryAcquisitionOptions,
} from "./repository-acquisition.js";
import type { GitHubScanJob } from "./scan-queue.js";

export interface GitHubAppWorkerQueue {
  claimNext(): Promise<GitHubScanJob | undefined>;
  release(jobId: string): Promise<GitHubScanJob>;
  fail(jobId: string): Promise<GitHubScanJob>;
  complete(jobId: string): Promise<boolean>;
}

export interface GitHubAppWorkerAuthorizer {
  isRepositoryAllowed(installationId: number, repository: string): Promise<boolean>;
}

export type GitHubInstallationTokenPurpose = "acquire" | "publish";

export interface GitHubAppWorkerOptions {
  queue: GitHubAppWorkerQueue;
  installationStore: GitHubAppWorkerAuthorizer;
  getInstallationToken(installationId: number, purpose: GitHubInstallationTokenPurpose): Promise<string>;
  scan(job: GitHubScanJob, workspace: string): Promise<SynSecReport>;
  publish(job: GitHubScanJob, report: SynSecReport, installationToken: string): Promise<void>;
  acquire?: (
    input: { repository: string; commitSha: string; installationToken: string },
    options?: GitHubRepositoryAcquisitionOptions,
  ) => Promise<AcquiredGitHubRepository>;
  acquisitionOptions?: GitHubRepositoryAcquisitionOptions;
}

export type GitHubAppWorkerResult =
  | { status: "idle" }
  | { status: "completed"; job: GitHubScanJob; reportId: string }
  | { status: "revoked"; job: GitHubScanJob }
  | { status: "retry_scheduled"; job: GitHubScanJob; error: string };

function safeError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.replace(/[\r\n]+/g, " ").trim().slice(0, 1000) || "GitHub App worker failed.";
}

/**
 * Consume at most one durable GitHub App scan job.
 *
 * Authorization is checked again after lease acquisition so a repository removed or suspended
 * after webhook queueing is never scanned from stale authorization. Installation credentials are
 * obtained only in the transport layer: one short-lived token for exact-commit acquisition and a
 * fresh token for publication. The scanner receives only the commit-pinned workspace and job
 * descriptor. Reports must bind to the exact queued head SHA before publication or completion.
 */
export async function runNextGitHubAppScanJob(options: GitHubAppWorkerOptions): Promise<GitHubAppWorkerResult> {
  const job = await options.queue.claimNext();
  if (!job) return { status: "idle" };

  let acquired: AcquiredGitHubRepository | undefined;
  try {
    const allowed = await options.installationStore.isRepositoryAllowed(job.installationId, job.repository);
    if (!allowed) {
      await options.queue.fail(job.jobId);
      return { status: "revoked", job };
    }

    const acquisitionToken = await options.getInstallationToken(job.installationId, "acquire");
    const acquire = options.acquire ?? acquireGitHubRepositoryCommit;
    acquired = await acquire({
      repository: job.repository,
      commitSha: job.headSha,
      installationToken: acquisitionToken,
    }, options.acquisitionOptions);

    if (acquired.repository !== job.repository || acquired.commitSha.toLowerCase() !== job.headSha.toLowerCase()) {
      throw new Error("Acquired GitHub repository does not match the leased scan job provenance.");
    }

    const report = await options.scan(job, acquired.workspace);
    const reportSha = report.target.commitSha?.trim().toLowerCase();
    if (!reportSha || reportSha !== job.headSha.toLowerCase()) {
      throw new Error("GitHub App worker report commit does not match the leased scan job head SHA.");
    }

    const publicationToken = await options.getInstallationToken(job.installationId, "publish");
    await options.publish(job, report, publicationToken);
    if (!await options.queue.complete(job.jobId)) {
      throw new Error("Completed GitHub App scan job disappeared before queue acknowledgement.");
    }
    return { status: "completed", job, reportId: report.reportId };
  } catch (error) {
    try {
      await options.queue.release(job.jobId);
    } catch (releaseError) {
      throw new Error(`${safeError(error)} Queue release also failed: ${safeError(releaseError)}`);
    }
    return { status: "retry_scheduled", job, error: safeError(error) };
  } finally {
    if (acquired) await acquired.cleanup();
  }
}
