import {
  buildSynSecGitHubAppCredentialRotationPlan,
  type SynSecGitHubAppCredentialRotationInput,
  type SynSecGitHubAppCredentialRotationPlan,
} from "./credential-rotation.js";

export type SynSecGitHubAppCredentialReloadKind = "webhook-secret" | "app-private-key";

export interface SynSecGitHubAppCredentialReloadReplica {
  replicaId: string;
  loadedGeneration: string;
  ready: boolean;
}

export interface SynSecGitHubAppCredentialReloadInput {
  kind: SynSecGitHubAppCredentialReloadKind;
  targetGeneration: string;
  expectedReplicaIds: readonly string[];
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
  unexpectedReplicaCount: number;
  complete: boolean;
  interpretation: "deployment-observed-reload-state-not-secret-management";
}

export type SynSecGitHubAppRotationWithoutReload = Omit<
  SynSecGitHubAppCredentialRotationInput,
  "runtimeReloaded"
>;

export interface SynSecGitHubAppCredentialRotationWithReloadInput {
  rotation: SynSecGitHubAppRotationWithoutReload;
  reload: SynSecGitHubAppCredentialReloadInput;
}

export interface SynSecGitHubAppCredentialRotationWithReloadAssessment {
  reload: SynSecGitHubAppCredentialReloadAssessment;
  rotation: SynSecGitHubAppCredentialRotationPlan;
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

function requireExpectedReplicaIds(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_REPLICA_COUNT) {
    throw new Error(`expectedReplicaIds must contain between 1 and ${MAX_REPLICA_COUNT} entries.`);
  }

  const ids: string[] = [];
  const seen = new Set<string>();
  for (const raw of value) {
    const replicaId = requireIdentifier(raw, "expectedReplicaId");
    if (seen.has(replicaId)) throw new Error("expectedReplicaIds must contain unique replica identifiers.");
    seen.add(replicaId);
    ids.push(replicaId);
  }
  return ids;
}

/**
 * Assess whether every specifically expected SynSec application replica has observed the same
 * credential configuration generation after a rollout.
 *
 * Generation and replica identifiers are deployment metadata only; credential values are not
 * accepted. Callers are responsible for obtaining these observations from their supervisor or
 * orchestration platform. A complete assessment proves only that the exact declared replica set is
 * ready and reports the target generation. It does not prove that GitHub accepted a webhook
 * secret/private key, revoke an old credential, or authorize repository access.
 */
export function assessSynSecGitHubAppCredentialReload(
  input: SynSecGitHubAppCredentialReloadInput,
): SynSecGitHubAppCredentialReloadAssessment {
  if (input.kind !== "webhook-secret" && input.kind !== "app-private-key") {
    throw new Error("GitHub App credential reload kind must be webhook-secret or app-private-key.");
  }

  const targetGeneration = requireIdentifier(input.targetGeneration, "targetGeneration");
  const expectedReplicaIds = requireExpectedReplicaIds(input.expectedReplicaIds);
  const expectedReplicaSet = new Set(expectedReplicaIds);
  if (!Array.isArray(input.replicas)) throw new Error("replicas must be an array.");
  if (input.replicas.length > MAX_REPLICA_COUNT) {
    throw new Error(`replicas must contain no more than ${MAX_REPLICA_COUNT} entries.`);
  }

  const observedReplicaIds = new Set<string>();
  let matchedReplicaCount = 0;
  let staleReplicaCount = 0;
  let unreadyReplicaCount = 0;
  let unexpectedReplicaCount = 0;

  for (const replica of input.replicas) {
    if (!replica || typeof replica !== "object") throw new Error("Every replica observation must be an object.");
    const replicaId = requireIdentifier(replica.replicaId, "replicaId");
    if (observedReplicaIds.has(replicaId)) throw new Error("Replica observations must use unique replicaId values.");
    observedReplicaIds.add(replicaId);

    const loadedGeneration = requireIdentifier(replica.loadedGeneration, "loadedGeneration");
    if (typeof replica.ready !== "boolean") throw new Error("replica.ready must be boolean.");

    if (!expectedReplicaSet.has(replicaId)) {
      unexpectedReplicaCount += 1;
      continue;
    }

    if (loadedGeneration === targetGeneration) matchedReplicaCount += 1;
    else staleReplicaCount += 1;
    if (!replica.ready) unreadyReplicaCount += 1;
  }

  const expectedReplicaCount = expectedReplicaIds.length;
  const observedReplicaCount = input.replicas.length;
  let missingReplicaCount = 0;
  for (const expectedReplicaId of expectedReplicaIds) {
    if (!observedReplicaIds.has(expectedReplicaId)) missingReplicaCount += 1;
  }

  const complete = missingReplicaCount === 0
    && unexpectedReplicaCount === 0
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
    unexpectedReplicaCount,
    complete,
    interpretation: "deployment-observed-reload-state-not-secret-management",
  };
}

/**
 * Compose deployment-wide reload observations with the existing credential-rotation state machine.
 * The reload acknowledgement is derived internally from the raw observations so callers cannot
 * substitute a hand-authored `complete: true` assessment. This remains an observation/evaluation
 * boundary: it does not retrieve secrets, reload processes, contact GitHub, or revoke credentials.
 */
export function buildSynSecGitHubAppCredentialRotationWithReloadAssessment(
  input: SynSecGitHubAppCredentialRotationWithReloadInput,
): SynSecGitHubAppCredentialRotationWithReloadAssessment {
  if (input.rotation.kind !== input.reload.kind) {
    throw new Error("Credential rotation and reload kinds must match.");
  }

  const reload = assessSynSecGitHubAppCredentialReload(input.reload);
  const rotation = buildSynSecGitHubAppCredentialRotationPlan({
    ...input.rotation,
    runtimeReloaded: reload.complete,
  });

  return { reload, rotation };
}
