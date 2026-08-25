export type SynSecGitHubAppUpgradeIssueCode =
  | "invalid-release-id"
  | "invalid-schema-version"
  | "invalid-observation-time"
  | "duplicate-replica"
  | "missing-replica"
  | "unexpected-replica"
  | "stale-observation"
  | "future-observation"
  | "replica-not-ready"
  | "mixed-schema"
  | "target-schema-mismatch"
  | "worker-admission-open"
  | "active-work-remains"
  | "rollback-schema-incompatible"
  | "previous-release-unavailable";

export interface SynSecGitHubAppReplicaUpgradeObservation {
  replicaId: string;
  releaseId: string;
  schemaVersion: number;
  ready: boolean;
  /** True only while this replica can admit a new background worker run/queue claim. */
  acceptingWorkerRuns: boolean;
  /** Durable fenced leases observed from the shared backend, not the local worker-run count. */
  activeLeases: number;
  observedAt: string;
}

export interface SynSecGitHubAppUpgradeAssessmentInput {
  currentReleaseId: string;
  targetReleaseId: string;
  currentSchemaVersion: number;
  targetSchemaVersion: number;
  expectedReplicaIds: readonly string[];
  replicas: readonly SynSecGitHubAppReplicaUpgradeObservation[];
  assessedAt: string;
  /** Maximum acceptable age for supervisor observations. Defaults to 5 minutes. */
  maxObservationAgeMs?: number;
  /** Operator assertion that the previous immutable application artifact is still deployable. */
  previousReleaseAvailable: boolean;
  /** Explicit migration property. False means a schema change blocks automatic rollback. */
  rollbackSchemaCompatible: boolean;
}

export interface SynSecGitHubAppUpgradeIssue {
  code: SynSecGitHubAppUpgradeIssueCode;
  replicaId?: string;
}

export interface SynSecGitHubAppUpgradeAssessment {
  readyToBeginRollout: boolean;
  readyToFinalizeRollout: boolean;
  rollbackAllowed: boolean;
  targetReplicaCount: number;
  previousReplicaCount: number;
  issues: SynSecGitHubAppUpgradeIssue[];
}

const DEFAULT_MAX_OBSERVATION_AGE_MS = 5 * 60 * 1000;
const MIN_MAX_OBSERVATION_AGE_MS = 10_000;
const MAX_MAX_OBSERVATION_AGE_MS = 60 * 60 * 1000;
const MAX_REPLICAS = 1_000;
const MAX_RELEASE_ID_LENGTH = 128;
const RELEASE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const REPLICA_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;

function releaseId(value: string): string | undefined {
  return typeof value === "string"
    && value.length <= MAX_RELEASE_ID_LENGTH
    && RELEASE_ID_PATTERN.test(value)
    ? value
    : undefined;
}

function replicaId(value: string): string | undefined {
  return typeof value === "string"
    && value.length <= 128
    && REPLICA_ID_PATTERN.test(value)
    ? value
    : undefined;
}

function schemaVersion(value: number): number | undefined {
  return Number.isSafeInteger(value) && value > 0 && value <= 2_147_483_647 ? value : undefined;
}

function canonicalTimestamp(value: string): number | undefined {
  if (typeof value !== "string" || value.length > 64) return undefined;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return undefined;
  return new Date(parsed).toISOString() === value ? parsed : undefined;
}

function maxObservationAge(value: number | undefined): number {
  const resolved = value ?? DEFAULT_MAX_OBSERVATION_AGE_MS;
  if (!Number.isSafeInteger(resolved) || resolved < MIN_MAX_OBSERVATION_AGE_MS || resolved > MAX_MAX_OBSERVATION_AGE_MS) {
    throw new Error(
      `GitHub App upgrade observation age must be between ${MIN_MAX_OBSERVATION_AGE_MS} and ${MAX_MAX_OBSERVATION_AGE_MS} milliseconds.`,
    );
  }
  return resolved;
}

/**
 * Assess one rolling GitHub App release transition from trusted supervisor observations.
 *
 * This function never performs a deployment, migration, drain, credential operation, or rollback.
 * It is a fail-closed gate for an external service manager. A replica is drained only when worker
 * admission is closed and the shared durable backend reports zero active fenced leases. A local
 * zero-run observation or a momentary zero-lease count while admission remains open is insufficient.
 * Repository content, webhook input, and scanner output must never supply these observations.
 */
export function assessSynSecGitHubAppUpgrade(
  input: SynSecGitHubAppUpgradeAssessmentInput,
): SynSecGitHubAppUpgradeAssessment {
  const issues: SynSecGitHubAppUpgradeIssue[] = [];
  const currentRelease = releaseId(input.currentReleaseId);
  const targetRelease = releaseId(input.targetReleaseId);
  if (!currentRelease || !targetRelease || currentRelease === targetRelease) {
    issues.push({ code: "invalid-release-id" });
  }

  const currentSchema = schemaVersion(input.currentSchemaVersion);
  const targetSchema = schemaVersion(input.targetSchemaVersion);
  if (!currentSchema || !targetSchema) issues.push({ code: "invalid-schema-version" });

  const assessedAt = canonicalTimestamp(input.assessedAt);
  if (assessedAt === undefined) issues.push({ code: "invalid-observation-time" });
  const ageLimit = maxObservationAge(input.maxObservationAgeMs);

  if (!Array.isArray(input.expectedReplicaIds) || input.expectedReplicaIds.length < 1 || input.expectedReplicaIds.length > MAX_REPLICAS) {
    issues.push({ code: "missing-replica" });
  }
  const expected = new Set<string>();
  for (const raw of input.expectedReplicaIds) {
    const id = replicaId(raw);
    if (!id || expected.has(id)) {
      issues.push({ code: "duplicate-replica", ...(id ? { replicaId: id } : {}) });
      continue;
    }
    expected.add(id);
  }

  const seen = new Set<string>();
  let targetReplicaCount = 0;
  let previousReplicaCount = 0;
  let allReady = true;
  let allDrained = true;
  let allTargetSchema = true;

  for (const observation of input.replicas) {
    const id = replicaId(observation.replicaId);
    if (!id || seen.has(id)) {
      issues.push({ code: "duplicate-replica", ...(id ? { replicaId: id } : {}) });
      continue;
    }
    seen.add(id);
    if (!expected.has(id)) issues.push({ code: "unexpected-replica", replicaId: id });

    const observedAt = canonicalTimestamp(observation.observedAt);
    if (observedAt === undefined || assessedAt === undefined) {
      issues.push({ code: "invalid-observation-time", replicaId: id });
    } else {
      if (observedAt > assessedAt + 30_000) issues.push({ code: "future-observation", replicaId: id });
      if (assessedAt - observedAt > ageLimit) issues.push({ code: "stale-observation", replicaId: id });
    }

    if (!observation.ready) {
      allReady = false;
      issues.push({ code: "replica-not-ready", replicaId: id });
    }
    if (observation.acceptingWorkerRuns !== false) {
      allDrained = false;
      issues.push({ code: "worker-admission-open", replicaId: id });
    }
    if (!Number.isSafeInteger(observation.activeLeases) || observation.activeLeases < 0 || observation.activeLeases > 1_000_000) {
      allDrained = false;
      issues.push({ code: "active-work-remains", replicaId: id });
    } else if (observation.activeLeases > 0) {
      allDrained = false;
      issues.push({ code: "active-work-remains", replicaId: id });
    }

    const observedSchema = schemaVersion(observation.schemaVersion);
    if (!observedSchema) {
      allTargetSchema = false;
      issues.push({ code: "invalid-schema-version", replicaId: id });
    } else if (targetSchema && observedSchema !== targetSchema) {
      allTargetSchema = false;
      issues.push({ code: observation.releaseId === targetRelease ? "target-schema-mismatch" : "mixed-schema", replicaId: id });
    }

    if (observation.releaseId === targetRelease) targetReplicaCount += 1;
    else if (observation.releaseId === currentRelease) previousReplicaCount += 1;
    else issues.push({ code: "invalid-release-id", replicaId: id });
  }

  for (const id of expected) {
    if (!seen.has(id)) issues.push({ code: "missing-replica", replicaId: id });
  }

  const structuralErrors = issues.some((issue) => [
    "invalid-release-id",
    "invalid-schema-version",
    "invalid-observation-time",
    "duplicate-replica",
    "missing-replica",
    "unexpected-replica",
    "stale-observation",
    "future-observation",
  ].includes(issue.code));

  const schemaChanged = currentSchema !== undefined && targetSchema !== undefined && currentSchema !== targetSchema;
  const rollbackAllowed = !structuralErrors
    && input.previousReleaseAvailable
    && (!schemaChanged || input.rollbackSchemaCompatible);
  if (!input.previousReleaseAvailable) issues.push({ code: "previous-release-unavailable" });
  if (schemaChanged && !input.rollbackSchemaCompatible) issues.push({ code: "rollback-schema-incompatible" });

  const exactReplicaCoverage = seen.size === expected.size && [...seen].every((id) => expected.has(id));
  const readyToBeginRollout = !structuralErrors
    && exactReplicaCoverage
    && rollbackAllowed
    && allReady
    && allDrained
    && previousReplicaCount === expected.size
    && targetReplicaCount === 0;

  const readyToFinalizeRollout = !structuralErrors
    && exactReplicaCoverage
    && allReady
    && allDrained
    && allTargetSchema
    && targetReplicaCount === expected.size
    && previousReplicaCount === 0;

  return {
    readyToBeginRollout,
    readyToFinalizeRollout,
    rollbackAllowed,
    targetReplicaCount,
    previousReplicaCount,
    issues,
  };
}
