import type { SynSecReport } from "@synsec/report";
import {
  acquireGitHubRepositoryScanTarget,
  type AcquiredGitHubScanTarget,
  type GitHubRepositoryAcquisitionOptions,
} from "./repository-acquisition.js";
import type { GitHubScanJob } from "./scan-queue.js";

export interface GitHubAppWorkerQueue {
  leaseMs?: number;
  claimNext(): Promise<GitHubScanJob | undefined>;
  assertLease(jobId: string, expectedLeaseId: string): Promise<GitHubScanJob>;
  renew?(jobId: string, expectedLeaseId: string): Promise<GitHubScanJob>;
  release(jobId: string, expectedLeaseId: string): Promise<GitHubScanJob>;
  fail(jobId: string, expectedLeaseId: string): Promise<GitHubScanJob>;
  complete(jobId: string, expectedLeaseId: string): Promise<boolean>;
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

interface LeaseHeartbeat {
  stop(): Promise<void>;
  assertHealthy(): void;
}

function startLeaseHeartbeat(queue: GitHubAppWorkerQueue, job: GitHubScanJob): LeaseHeartbeat {
  if (!queue.renew || !queue.leaseMs || !job.leaseId) {
    return { stop: async () => {}, assertHealthy: () => {} };
  }

  const intervalMs = Math.max(1_000, Math.floor(queue.leaseMs / 3));
  let stopped = false;
  let failure: unknown;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let inFlight: Promise<void> | undefined;

  const schedule = (): void => {
    if (stopped || failure) return;
    timer = setTimeout(() => {
      inFlight = (async () => {
        try {
          await queue.renew?.(job.jobId, job.leaseId as string);
        } catch (error) {
          failure = error;
        } finally {
          inFlight = undefined;
          schedule();
        }
      })();
    }, intervalMs);
    timer.unref?.();
  };
  schedule();

  return {
    stop: async () => {
      stopped = true;
      if (timer) clearTimeout(timer);
      if (inFlight) await inFlight;
    },
    assertHealthy: () => {
      if (failure) throw new Error(`GitHub scan job lease renewal failed: ${safeError(failure)}`);
    },
  };
}

/**
 * Consume at most one durable GitHub App scan job.
 *
 * Authorization is checked again after lease acquisition so a repository removed or suspended
 * after webhook queueing is never scanned from stale authorization. Installation credentials are
 * obtained only in the transport layer: one short-lived token for exact-commit acquisition and a
 * fresh token for publication. For PR jobs, acquisition can also materialize the exact queued base
 * commit in a second isolated workspace without exposing credentials to the scanner. New leases use
 * a random durable lease id as a fencing token. The local queue renews that exact lease while work is
 * active, revalidates it immediately before publication, and requires the same id for retry/terminal
 * mutations so an expired or concurrently superseded worker cannot publish or mutate newer work.
 */
export async function runNextGitHubAppScanJob(options: GitHubAppWorkerOptions): Promise<GitHubAppWorkerResult> {
  const job = await options.queue.claimNext();
  if (!job) return { status: "idle" };
  const leaseId = job.leaseId?.trim();
  if (!leaseId) throw new Error("Claimed GitHub scan job is missing its lease fencing identity.");

  let acquired: AcquiredGitHubScanTarget | undefined;
  const heartbeat = startLeaseHeartbeat(options.queue, job);
  try {
    const allowed = await options.installationStore.isRepositoryAllowed(job.installationId, job.repository);
    if (!allowed) {
      await heartbeat.stop();
      heartbeat.assertHealthy();
      await options.queue.fail(job.jobId, leaseId);
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

    heartbeat.assertHealthy();
    await options.queue.assertLease(job.jobId, leaseId);
    const publicationToken = await options.getInstallationToken(job.installationId, "publish");
    await options.publish(job, report, publicationToken);
    await heartbeat.stop();
    heartbeat.assertHealthy();
    if (!await options.queue.complete(job.jobId, leaseId)) {
      throw new Error("Completed GitHub App scan job disappeared before queue acknowledgement.");
    }
    return { status: "completed", job, reportId: report.reportId };
  } catch (error) {
    await heartbeat.stop();
    let effectiveError: unknown = error;
    try {
      heartbeat.assertHealthy();
    } catch (heartbeatError) {
      effectiveError = new Error(`${safeError(error)} ${safeError(heartbeatError)}`);
    }
    try {
      await options.queue.release(job.jobId, leaseId);
    } catch (releaseError) {
      throw new Error(`${safeError(effectiveError)} Queue release also failed: ${safeError(releaseError)}`);
    }
    return { status: "retry_scheduled", job, error: safeError(effectiveError) };
  } finally {
    await heartbeat.stop();
    if (acquired) await acquired.cleanup();
  }
}
