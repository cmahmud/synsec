import {
  assessSynSecGitHubAppCredentialReload,
  type SynSecGitHubAppCredentialReloadKind,
  type SynSecGitHubAppCredentialReloadAssessment,
  type SynSecGitHubAppRotationWithoutReload,
} from "./credential-reload.js";
import {
  buildSynSecGitHubAppCredentialRotationPlan,
  type SynSecGitHubAppCredentialRotationPlan,
} from "./credential-rotation.js";

export interface SynSecGitHubAppFreshCredentialReloadReplica {
  replicaId: string;
  loadedGeneration: string;
  ready: boolean;
  observedAt: string;
}

export interface SynSecGitHubAppFreshCredentialReloadInput {
  kind: SynSecGitHubAppCredentialReloadKind;
  targetGeneration: string;
  expectedReplicaIds: readonly string[];
  replicas: readonly SynSecGitHubAppFreshCredentialReloadReplica[];
  assessedAt: string;
  maxObservationAgeSeconds?: number;
}

export interface SynSecGitHubAppFreshCredentialReloadAssessment {
  version: 1;
  reload: SynSecGitHubAppCredentialReloadAssessment;
  assessedAt: string;
  maxObservationAgeSeconds: number;
  freshReplicaCount: number;
  expiredObservationCount: number;
  futureObservationCount: number;
  complete: boolean;
  interpretation: "fresh-deployment-observation-not-secret-management";
}

export interface SynSecGitHubAppCredentialRotationWithFreshReloadInput {
  rotation: SynSecGitHubAppRotationWithoutReload;
  reload: SynSecGitHubAppFreshCredentialReloadInput;
}

export interface SynSecGitHubAppCredentialRotationWithFreshReloadAssessment {
  reload: SynSecGitHubAppFreshCredentialReloadAssessment;
  rotation: SynSecGitHubAppCredentialRotationPlan;
}

const DEFAULT_MAX_OBSERVATION_AGE_SECONDS = 300;
const MIN_MAX_OBSERVATION_AGE_SECONDS = 10;
const MAX_MAX_OBSERVATION_AGE_SECONDS = 3600;
const MAX_FUTURE_CLOCK_SKEW_MS = 30_000;

function parseTimestamp(value: unknown, name: string): { value: string; epochMs: number } {
  if (typeof value !== "string" || value.length < 20 || value.length > 40) {
    throw new Error(`${name} must be a bounded RFC 3339 timestamp.`);
  }
  const epochMs = Date.parse(value);
  if (!Number.isFinite(epochMs)) throw new Error(`${name} must be a valid RFC 3339 timestamp.`);
  const canonical = new Date(epochMs).toISOString();
  if (value !== canonical) {
    throw new Error(`${name} must use canonical UTC RFC 3339 format.`);
  }
  return { value, epochMs };
}

function maxObservationAgeSeconds(value: number | undefined): number {
  const normalized = value ?? DEFAULT_MAX_OBSERVATION_AGE_SECONDS;
  if (
    !Number.isSafeInteger(normalized)
    || normalized < MIN_MAX_OBSERVATION_AGE_SECONDS
    || normalized > MAX_MAX_OBSERVATION_AGE_SECONDS
  ) {
    throw new Error(
      `maxObservationAgeSeconds must be an integer between ${MIN_MAX_OBSERVATION_AGE_SECONDS} and ${MAX_MAX_OBSERVATION_AGE_SECONDS}.`,
    );
  }
  return normalized;
}

/**
 * Require fleet-wide credential reload observations to be both structurally complete and recent.
 *
 * The base reload assessor proves exact replica membership, generation agreement, and readiness.
 * This wrapper additionally prevents old observations from being reused indefinitely as retirement
 * evidence. It accepts deployment metadata only and never accepts or retrieves credential values.
 */
export function assessSynSecGitHubAppFreshCredentialReload(
  input: SynSecGitHubAppFreshCredentialReloadInput,
): SynSecGitHubAppFreshCredentialReloadAssessment {
  const assessedAt = parseTimestamp(input.assessedAt, "assessedAt");
  const maxAgeSeconds = maxObservationAgeSeconds(input.maxObservationAgeSeconds);
  const maxAgeMs = maxAgeSeconds * 1000;

  if (!Array.isArray(input.replicas)) throw new Error("replicas must be an array.");

  let freshReplicaCount = 0;
  let expiredObservationCount = 0;
  let futureObservationCount = 0;
  const baseReplicas = input.replicas.map((replica) => {
    if (!replica || typeof replica !== "object") throw new Error("Every replica observation must be an object.");
    const observedAt = parseTimestamp(replica.observedAt, "replica.observedAt");
    const ageMs = assessedAt.epochMs - observedAt.epochMs;
    if (ageMs < -MAX_FUTURE_CLOCK_SKEW_MS) futureObservationCount += 1;
    else if (ageMs > maxAgeMs) expiredObservationCount += 1;
    else freshReplicaCount += 1;

    return {
      replicaId: replica.replicaId,
      loadedGeneration: replica.loadedGeneration,
      ready: replica.ready,
    };
  });

  const reload = assessSynSecGitHubAppCredentialReload({
    kind: input.kind,
    targetGeneration: input.targetGeneration,
    expectedReplicaIds: input.expectedReplicaIds,
    replicas: baseReplicas,
  });
  const complete = reload.complete
    && expiredObservationCount === 0
    && futureObservationCount === 0
    && freshReplicaCount === reload.expectedReplicaCount;

  return {
    version: 1,
    reload,
    assessedAt: assessedAt.value,
    maxObservationAgeSeconds: maxAgeSeconds,
    freshReplicaCount,
    expiredObservationCount,
    futureObservationCount,
    complete,
    interpretation: "fresh-deployment-observation-not-secret-management",
  };
}

/**
 * Compose fresh fleet observations with credential rotation. `runtimeReloaded` is derived only from
 * the fresh assessment, so an otherwise complete rotation cannot retire the previous credential on
 * stale rollout evidence.
 */
export function buildSynSecGitHubAppCredentialRotationWithFreshReloadAssessment(
  input: SynSecGitHubAppCredentialRotationWithFreshReloadInput,
): SynSecGitHubAppCredentialRotationWithFreshReloadAssessment {
  if (input.rotation.kind !== input.reload.kind) {
    throw new Error("Credential rotation and fresh reload kinds must match.");
  }

  const reload = assessSynSecGitHubAppFreshCredentialReload(input.reload);
  const rotation = buildSynSecGitHubAppCredentialRotationPlan({
    ...input.rotation,
    runtimeReloaded: reload.complete,
  });
  return { reload, rotation };
}
