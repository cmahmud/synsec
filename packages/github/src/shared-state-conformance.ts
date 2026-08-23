import {
  REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES,
  type GitHubAppSharedStateCapability,
} from "./app-deployment.js";

export type GitHubAppSharedStateConformanceRisk =
  | "duplicate-processing"
  | "stale-worker"
  | "authorization-race"
  | "partial-state";

export interface GitHubAppSharedStateConformanceScenario {
  id: string;
  capability: GitHubAppSharedStateCapability;
  risk: GitHubAppSharedStateConformanceRisk;
  invariant: string;
}

/**
 * Stable minimum adversarial scenarios a shared-state adapter must exercise against its real
 * backend before SynSec can treat the capability declaration as supported by conformance evidence.
 */
export const GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS = [
  {
    id: "replay.concurrent-duplicate-claim",
    capability: "atomicReplayClaim",
    risk: "duplicate-processing",
    invariant: "Concurrent claims for one delivery admit at most one accepted replay claim.",
  },
  {
    id: "queue.concurrent-idempotent-insert",
    capability: "atomicQueueInsertion",
    risk: "duplicate-processing",
    invariant: "Concurrent insertion of the same logical scan work produces one durable job identity.",
  },
  {
    id: "queue.concurrent-claim-fence",
    capability: "atomicQueueClaimWithFence",
    risk: "stale-worker",
    invariant: "Competing workers cannot both hold a valid lease, and every successful claim receives a fresh fence.",
  },
  {
    id: "queue.stale-fence-renewal",
    capability: "compareAndSetLeaseRenewal",
    risk: "stale-worker",
    invariant: "A superseded fence cannot renew a newer lease.",
  },
  {
    id: "queue.stale-fence-terminal-transitions",
    capability: "fencedQueueTransitions",
    risk: "stale-worker",
    invariant: "A superseded fence cannot release, fail, or complete work owned by a newer lease.",
  },
  {
    id: "installation.concurrent-selection-mutation",
    capability: "transactionalInstallationState",
    risk: "partial-state",
    invariant: "Concurrent installation and repository-selection mutations expose only complete authorization states.",
  },
  {
    id: "authorization.cross-replica-revocation",
    capability: "sharedAuthorizationState",
    risk: "authorization-race",
    invariant: "Authorization removal becomes authoritative for independent intake and worker replicas before further protected work proceeds.",
  },
] as const satisfies readonly GitHubAppSharedStateConformanceScenario[];

export interface GitHubAppSharedStateConformanceCoverageAssessment {
  complete: boolean;
  coveredScenarioIds: string[];
  missingScenarioIds: string[];
  missingCapabilities: GitHubAppSharedStateCapability[];
}

const REQUIRED_SCENARIO_IDS = new Set(GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.map((scenario) => scenario.id));

/**
 * Assess scenario coverage from bounded scenario identifiers produced by an adapter's real-backend
 * test suite. Unknown identifiers are ignored so callers cannot satisfy the contract with arbitrary
 * free-form evidence. This function does not execute or trust a database by itself.
 */
export function assessGitHubAppSharedStateConformanceCoverage(
  completedScenarioIds: readonly string[],
): GitHubAppSharedStateConformanceCoverageAssessment {
  const covered = new Set<string>();
  for (const id of completedScenarioIds) {
    if (typeof id === "string" && REQUIRED_SCENARIO_IDS.has(id)) covered.add(id);
  }

  const coveredScenarioIds = GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS
    .filter((scenario) => covered.has(scenario.id))
    .map((scenario) => scenario.id);
  const missingScenarioIds = GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS
    .filter((scenario) => !covered.has(scenario.id))
    .map((scenario) => scenario.id);
  const missingCapabilitySet = new Set(
    GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS
      .filter((scenario) => !covered.has(scenario.id))
      .map((scenario) => scenario.capability),
  );
  const missingCapabilities = REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES.filter(
    (capability) => missingCapabilitySet.has(capability),
  );

  return {
    complete: missingScenarioIds.length === 0,
    coveredScenarioIds,
    missingScenarioIds,
    missingCapabilities: [...missingCapabilities],
  };
}
