import type { GitHubAppRuntimeStatus } from "./app-status.js";

export type GitHubAppRuntimeReadinessCode =
  | "invalid-status"
  | "expired-leases"
  | "pending-backlog"
  | "failed-backlog";

export interface GitHubAppRuntimeReadinessPolicy {
  /** Maximum expired leases allowed before routing readiness fails. Defaults to 0. */
  maxExpiredLeases?: number;
  /** Optional maximum pending queue depth. Omit when backlog size is not a routing signal. */
  maxPendingJobs?: number;
  /** Optional maximum retained failed-job count. Omit when failures are not a routing signal. */
  maxFailedJobs?: number;
}

export interface GitHubAppRuntimeReadinessAssessment {
  ready: boolean;
  codes: GitHubAppRuntimeReadinessCode[];
  interpretation: "aggregate-runtime-routing-policy-not-security-certification";
}

const MAX_COUNT = 1_000_000_000;

function boundedThreshold(value: number | undefined, name: string): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_COUNT) {
    throw new Error(`${name} must be an integer between 0 and ${MAX_COUNT}.`);
  }
  return value;
}

function boundedCount(value: unknown): value is number {
  return typeof value === "number"
    && Number.isSafeInteger(value)
    && value >= 0
    && value <= MAX_COUNT;
}

function statusIsConsistent(status: GitHubAppRuntimeStatus): boolean {
  const installationCounts = [
    status.installations.total,
    status.installations.active,
    status.installations.suspended,
    status.installations.allRepositories,
    status.installations.selectedRepositories,
  ];
  const queueCounts = [
    status.queue.total,
    status.queue.pending,
    status.queue.leased,
    status.queue.expiredLeases,
    status.queue.failed,
  ];
  if (![...installationCounts, ...queueCounts].every(boundedCount)) return false;
  if (status.installations.active + status.installations.suspended !== status.installations.total) return false;
  if (status.installations.allRepositories + status.installations.selectedRepositories !== status.installations.total) return false;
  if (status.queue.pending + status.queue.leased + status.queue.failed !== status.queue.total) return false;
  if (status.queue.expiredLeases > status.queue.leased) return false;
  return true;
}

/**
 * Evaluate aggregate hosted-runtime state for routing readiness without exposing tenant identity.
 *
 * The default policy fails on any expired lease because an expired worker lease indicates reclaimable
 * work and can signal a stalled/lost worker. Pending/failed backlog thresholds are opt-in because
 * acceptable queue depth is deployment-specific. This policy does not certify scanner isolation,
 * shared-state safety, GitHub authorization, or credential correctness.
 */
export function assessGitHubAppRuntimeReadiness(
  status: GitHubAppRuntimeStatus,
  policy: GitHubAppRuntimeReadinessPolicy = {},
): GitHubAppRuntimeReadinessAssessment {
  const maxExpiredLeases = boundedThreshold(policy.maxExpiredLeases ?? 0, "maxExpiredLeases") ?? 0;
  const maxPendingJobs = boundedThreshold(policy.maxPendingJobs, "maxPendingJobs");
  const maxFailedJobs = boundedThreshold(policy.maxFailedJobs, "maxFailedJobs");
  const codes: GitHubAppRuntimeReadinessCode[] = [];

  if (!statusIsConsistent(status)) {
    codes.push("invalid-status");
  } else {
    if (status.queue.expiredLeases > maxExpiredLeases) codes.push("expired-leases");
    if (maxPendingJobs !== undefined && status.queue.pending > maxPendingJobs) codes.push("pending-backlog");
    if (maxFailedJobs !== undefined && status.queue.failed > maxFailedJobs) codes.push("failed-backlog");
  }

  return {
    ready: codes.length === 0,
    codes,
    interpretation: "aggregate-runtime-routing-policy-not-security-certification",
  };
}

/** Build the minimal boolean predicate accepted by createGitHubAppServer(). */
export function createGitHubAppRuntimeReadinessPredicate(
  policy: GitHubAppRuntimeReadinessPolicy = {},
): (status: GitHubAppRuntimeStatus) => boolean {
  // Validate the policy once at construction time rather than only on the first probe.
  boundedThreshold(policy.maxExpiredLeases ?? 0, "maxExpiredLeases");
  boundedThreshold(policy.maxPendingJobs, "maxPendingJobs");
  boundedThreshold(policy.maxFailedJobs, "maxFailedJobs");
  return (status) => assessGitHubAppRuntimeReadiness(status, policy).ready;
}
