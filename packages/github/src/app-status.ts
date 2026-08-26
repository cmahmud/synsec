import { FileGitHubInstallationStore } from "./installation-store.js";
import { FileGitHubScanQueue } from "./scan-queue.js";

export interface GitHubAppRuntimeStatus {
  installations: {
    total: number;
    active: number;
    suspended: number;
    allRepositories: number;
    selectedRepositories: number;
  };
  queue: {
    total: number;
    pending: number;
    leased: number;
    expiredLeases: number;
    failed: number;
  };
}

/**
 * Build an aggregate-only local status snapshot suitable for operator health surfaces.
 *
 * The snapshot deliberately omits installation ids, account names, repository names, commit SHAs,
 * delivery ids, source paths, credentials, scanner output, and arbitrary durable-record fields.
 * Durable stores still validate every record before aggregation, so malformed state fails closed.
 * Expired leases remain counted as leased durable records but are surfaced separately because they
 * are immediately eligible for reclaim and are a useful signal of worker stalls or process loss.
 */
export async function buildGitHubAppRuntimeStatus(input: {
  installationStore: FileGitHubInstallationStore;
  queue: FileGitHubScanQueue;
  now?: () => number;
}): Promise<GitHubAppRuntimeStatus> {
  const [installations, jobs] = await Promise.all([
    input.installationStore.list(),
    input.queue.list(),
  ]);
  const now = (input.now ?? Date.now)();
  if (!Number.isFinite(now) || now <= 0) throw new Error("GitHub App status clock must be a positive timestamp.");

  let active = 0;
  let suspended = 0;
  let allRepositories = 0;
  let selectedRepositories = 0;
  for (const installation of installations) {
    if (installation.suspendedAt) suspended += 1;
    else active += 1;
    if (installation.repositorySelection === "all") allRepositories += 1;
    else selectedRepositories += 1;
  }

  let pending = 0;
  let leased = 0;
  let expiredLeases = 0;
  let failed = 0;
  for (const job of jobs) {
    if (job.status === "pending") pending += 1;
    else if (job.status === "leased") {
      leased += 1;
      if (Date.parse(job.leaseUntil ?? "") <= now) expiredLeases += 1;
    } else failed += 1;
  }

  return {
    installations: {
      total: installations.length,
      active,
      suspended,
      allRepositories,
      selectedRepositories,
    },
    queue: {
      total: jobs.length,
      pending,
      leased,
      expiredLeases,
      failed,
    },
  };
}
