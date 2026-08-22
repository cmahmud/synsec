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
    failed: number;
  };
}

/**
 * Build an aggregate-only local status snapshot suitable for operator health surfaces.
 *
 * The snapshot deliberately omits installation ids, account names, repository names, commit SHAs,
 * delivery ids, source paths, credentials, scanner output, and arbitrary durable-record fields.
 * Durable stores still validate every record before aggregation, so malformed state fails closed.
 */
export async function buildGitHubAppRuntimeStatus(input: {
  installationStore: FileGitHubInstallationStore;
  queue: FileGitHubScanQueue;
}): Promise<GitHubAppRuntimeStatus> {
  const [installations, jobs] = await Promise.all([
    input.installationStore.list(),
    input.queue.list(),
  ]);

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
  let failed = 0;
  for (const job of jobs) {
    if (job.status === "pending") pending += 1;
    else if (job.status === "leased") leased += 1;
    else failed += 1;
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
      failed,
    },
  };
}
