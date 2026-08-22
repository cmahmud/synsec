import type { SynSecReport } from "@synsec/report";
import {
  acquireGitHubRepositoryScanTarget,
  type AcquiredGitHubScanTarget,
  type GitHubRepositoryAcquisitionOptions,
} from "./repository-acquisition.js";
import type { GitHubScanJob } from "./scan-queue.js";

export interface GitHubAppWorkerQueue {
  claimNext(): Promise<GitHubScanJob | undefined>;
  assertLease(jobId: string, expectedAttempts: number): Promise<GitHubScanJob>;
  release(jobId: string, expectedAttempts: number): Promise<GitHubScanJob>;
  fail(jobId: string, expectedAttempts: number): Promise<GitHubScanJob>;
  complete(jobId: string, expectedAttempts: number): Promise<boolean>;
}

export interface GitHubAppWorkerAuthorizer {
  isRepositoryAllowed(installationId: number, repository: string): Promise<boolean>;
}

export type GitHubInstallationTokenPurpose = "acquire" | "publish";

export interface GitHubAppWorkerOptions {
  queue: GitHubAppWorkerQueue;
  installationStore: GitHubAppWorkerAuthorizer;
  getInstallationToken(installationId: number, purpose: GitHubInstallationTokenPurpose): Promise<string>;
  scan(job: GitHubScanJob, workspace: string, baseWorkspace?: string): Promise<SynSecReport>;
  publish(job: GitHubScanJob, report: SynSecReport, installationToken: string): Promise<void>;
  acquire?: (
    input: { repository: string; commitSha: string; baseCommitSha?: string; installationToken: string },
    options?: GitHubRepositoryAcquisitionOptions,
  ) => Promise<AcquiredGitHubScanTarget>;
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
 * fresh token for publication. For PR jobs, acquisition can also materialize the exact queued base
 * commit in a second isolated workspace without exposing credentials to the scanner. Reports must
 * bind to the exact queued head SHA before publication or completion. The queue lease generation is
 * revalidated immediately before publication and on every retry/terminal mutation so an expired,
 * reclaimed worker cannot publish or mutate a newer worker's lease.
 */
export async function runNextGitHubAppScanJob(options: GitHubAppWorkerOptions): Promise<GitHubAppWorkerResult> {
  const job = await options.queue.claimNext();
  if (!job) return { status: "idle" };

  let acquired: AcquiredGitHubScanTarget | undefined;
  try {
    const allowed = await options.installationStore.isRepositoryAllowed(job.installationId, job.repository);
    if (!allowed) {
      await options.queue.fail(job.jobId, job.attempts);
      return { status: "revoked", job };
    }

    const acquisitionToken = await options.getInstallationToken(job.installationId, "acquire");
    const acquire = options.acquire ?? acquireGitHubRepositoryScanTarget;
    acquired = await acquire({
      repository: job.repository,
      commitSha: job.headSha,
      ...(job.event === "pull_request" && job.baseSha ? { baseCommitSha: job.baseSha } : {}),
      installationToken: acquisitionToken,
    }, options.acquisitionOptions);

    if (acquired.repository !== job.repository || acquired.commitSha.toLowerCase() !== job.headSha.toLowerCase()) {
      throw new Error("Acquired GitHub repository does not match the leased scan job provenance.");
    }
    if (job.event === "pull_request") {
      const acquiredBaseSha = acquired.base?.commitSha.toLowerCase();
      if (!job.baseSha || !acquiredBaseSha || acquiredBaseSha !== job.baseSha.toLowerCase()) {
        throw new Error("Acquired GitHub base repository does not match the leased pull-request base SHA.");
      }
    }

    const report = await options.scan(job, acquired.workspace, acquired.base?.workspace);
    const reportSha = report.target.commitSha?.trim().toLowerCase();
    if (!reportSha || reportSha !== job.headSha.toLowerCase()) {
      throw new Error("GitHub App worker report commit does not match the leased scan job head SHA.");
    }

    await options.queue.assertLease(job.jobId, job.attempts);
    const publicationToken = await options.getInstallationToken(job.installationId, "publish");
    await options.publish(job, report, publicationToken);
    if (!await options.queue.complete(job.jobId, job.attempts)) {
      throw new Error("Completed GitHub App scan job disappeared before queue acknowledgement.");
    }
    return { status: "completed", job, reportId: report.reportId };
  } catch (error) {
    try {
      await options.queue.release(job.jobId, job.attempts);
    } catch (releaseError) {
      throw new Error(`${safeError(error)} Queue release also failed: ${safeError(releaseError)}`);
    }
    return { status: "retry_scheduled", job, error: safeError(error) };
  } finally {
    if (acquired) await acquired.cleanup();
  }
}
