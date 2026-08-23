export type SynSecGitHubAppCredentialReloadKind = "webhook-secret" | "app-private-key";

export interface SynSecGitHubAppCredentialReloadReplica {
  replicaId: string;
  loadedGeneration: string;
  ready: boolean;
}

export interface SynSecGitHubAppCredentialReloadInput {
  kind: SynSecGitHubAppCredentialReloadKind;
  targetGeneration: string;
  expectedReplicaCount: number;
  replicas: readonly SynSecGitHubAppCredentialReloadReplica[];
}

export interface SynSecGitHubAppCredentialReloadAssessment {
  version: 1;
  kind: SynSecGitHubAppCredentialReloadKind;
  targetGeneration: string;
  expectedReplicaCount: number;
  observedReplicaCount: number;
  matchedReplicaCount: number;
  staleReplicaCount: number;
  unreadyReplicaCount: number;
  missingReplicaCount: number;
  complete: boolean;
  interpretation: "deployment-observed-reload-state-not-secret-management";
}

const MAX_REPLICA_COUNT = 1000;
const MAX_IDENTIFIER_LENGTH = 128;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/;

function requireIdentifier(value: unknown, name: string): string {
  if (typeof value !== "string") throw new Error(`${name} must be a string.`);
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > MAX_IDENTIFIER_LENGTH || !SAFE_IDENTIFIER.test(trimmed)) {
    throw new Error(`${name} must be a bounded non-secret identifier.`);
  }
  return trimmed;
}

function requireReplicaCount(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > MAX_REPLICA_COUNT) {
    throw new Error(`expectedReplicaCount must be an integer between 1 and ${MAX_REPLICA_COUNT}.`);
  }
  return value as number;
}

/**
 * Assess whether every expected SynSec application replica has observed the same credential
 * configuration generation after a rollout.
 *
 * Generation and replica identifiers are deployment metadata only; credential values are not
 * accepted. Callers are responsible for obtaining these observations from their supervisor or
 * orchestration platform. A complete assessment proves only that all declared replicas are ready
 * and report the target generation. It does not prove that GitHub accepted a webhook secret/private
 * key, revoke an old credential, or authorize repository access.
 */
export function assessSynSecGitHubAppCredentialReload(
  input: SynSecGitHubAppCredentialReloadInput,
): SynSecGitHubAppCredentialReloadAssessment {
  if (input.kind !== "webhook-secret" && input.kind !== "app-private-key") {
    throw new Error("GitHub App credential reload kind must be webhook-secret or app-private-key.");
  }

  const targetGeneration = requireIdentifier(input.targetGeneration, "targetGeneration");
  const expectedReplicaCount = requireReplicaCount(input.expectedReplicaCount);
  if (!Array.isArray(input.replicas)) throw new Error("replicas must be an array.");
  if (input.replicas.length > MAX_REPLICA_COUNT) {
    throw new Error(`replicas must contain no more than ${MAX_REPLICA_COUNT} entries.`);
  }

  const replicaIds = new Set<string>();
  let matchedReplicaCount = 0;
  let staleReplicaCount = 0;
  let unreadyReplicaCount = 0;

  for (const replica of input.replicas) {
    if (!replica || typeof replica !== "object") throw new Error("Every replica observation must be an object.");
    const replicaId = requireIdentifier(replica.replicaId, "replicaId");
    if (replicaIds.has(replicaId)) throw new Error("Replica observations must use unique replicaId values.");
    replicaIds.add(replicaId);

    const loadedGeneration = requireIdentifier(replica.loadedGeneration, "loadedGeneration");
    if (typeof replica.ready !== "boolean") throw new Error("replica.ready must be boolean.");

    if (loadedGeneration === targetGeneration) matchedReplicaCount += 1;
    else staleReplicaCount += 1;
    if (!replica.ready) unreadyReplicaCount += 1;
  }

  const observedReplicaCount = input.replicas.length;
  const missingReplicaCount = Math.max(0, expectedReplicaCount - observedReplicaCount);
  const complete = observedReplicaCount === expectedReplicaCount
    && matchedReplicaCount === expectedReplicaCount
    && staleReplicaCount === 0
    && unreadyReplicaCount === 0;

  return {
    version: 1,
    kind: input.kind,
    targetGeneration,
    expectedReplicaCount,
    observedReplicaCount,
    matchedReplicaCount,
    staleReplicaCount,
    unreadyReplicaCount,
    missingReplicaCount,
    complete,
    interpretation: "deployment-observed-reload-state-not-secret-management",
  };
}

/**
 * Convert a deployment-wide reload assessment into the acknowledgement expected by the rotation
 * planner. This intentionally returns only a boolean so credential values and replica metadata do
 * not cross into the rotation state machine.
 */
export function credentialReloadAcknowledgement(
  assessment: SynSecGitHubAppCredentialReloadAssessment,
): boolean {
  if (assessment.version !== 1) throw new Error("Unsupported credential reload assessment version.");
  return assessment.complete === true;
}
