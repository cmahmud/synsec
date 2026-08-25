import assert from "node:assert/strict";
import test from "node:test";
import { assessSynSecGitHubAppUpgrade } from "@synsec/github/app-upgrade";

function replica(overrides = {}) {
  return {
    replicaId: "synsec-0",
    releaseId: "0.2.0-old",
    schemaVersion: 1,
    ready: true,
    acceptingWorkerRuns: false,
    activeLeases: 0,
    observedAt: "2026-08-25T03:00:00.000Z",
    ...overrides,
  };
}

function base(overrides = {}) {
  return {
    currentReleaseId: "0.2.0-old",
    targetReleaseId: "0.2.0-new",
    currentSchemaVersion: 1,
    targetSchemaVersion: 1,
    expectedReplicaIds: ["synsec-0", "synsec-1"],
    replicas: [
      replica(),
      replica({ replicaId: "synsec-1" }),
    ],
    assessedAt: "2026-08-25T03:01:00.000Z",
    previousReleaseAvailable: true,
    rollbackSchemaCompatible: true,
    ...overrides,
  };
}

test("rolling upgrade can begin only from an exact healthy drained previous fleet", () => {
  const result = assessSynSecGitHubAppUpgrade(base());
  assert.equal(result.readyToBeginRollout, true);
  assert.equal(result.readyToFinalizeRollout, false);
  assert.equal(result.rollbackAllowed, true);
  assert.equal(result.previousReplicaCount, 2);
  assert.equal(result.targetReplicaCount, 0);
});

test("rolling upgrade can finalize only when the exact fleet is healthy, drained, and on the target release/schema", () => {
  const result = assessSynSecGitHubAppUpgrade(base({
    replicas: [
      replica({ releaseId: "0.2.0-new" }),
      replica({ replicaId: "synsec-1", releaseId: "0.2.0-new" }),
    ],
  }));
  assert.equal(result.readyToBeginRollout, false);
  assert.equal(result.readyToFinalizeRollout, true);
  assert.equal(result.targetReplicaCount, 2);
  assert.equal(result.previousReplicaCount, 0);
});

test("zero durable leases do not count as drained while worker admission remains open", () => {
  const result = assessSynSecGitHubAppUpgrade(base({
    replicas: [
      replica({ acceptingWorkerRuns: true, activeLeases: 0 }),
      replica({ replicaId: "synsec-1" }),
    ],
  }));
  assert.equal(result.readyToBeginRollout, false);
  assert.equal(result.readyToFinalizeRollout, false);
  assert.ok(result.issues.some((issue) => issue.code === "worker-admission-open" && issue.replicaId === "synsec-0"));
});

test("active leases prevent both rollout start and finalization", () => {
  const result = assessSynSecGitHubAppUpgrade(base({
    replicas: [
      replica({ activeLeases: 1 }),
      replica({ replicaId: "synsec-1" }),
    ],
  }));
  assert.equal(result.readyToBeginRollout, false);
  assert.equal(result.readyToFinalizeRollout, false);
  assert.ok(result.issues.some((issue) => issue.code === "active-work-remains" && issue.replicaId === "synsec-0"));
});

test("schema-changing rollout cannot begin when rollback compatibility is not explicitly available", () => {
  const result = assessSynSecGitHubAppUpgrade(base({
    currentSchemaVersion: 1,
    targetSchemaVersion: 2,
    replicas: [
      replica({ schemaVersion: 1 }),
      replica({ replicaId: "synsec-1", schemaVersion: 1 }),
    ],
    rollbackSchemaCompatible: false,
  }));
  assert.equal(result.rollbackAllowed, false);
  assert.equal(result.readyToBeginRollout, false);
  assert.ok(result.issues.some((issue) => issue.code === "rollback-schema-incompatible"));
});

test("stale, duplicate, missing, or unexpected replica observations fail closed", () => {
  const result = assessSynSecGitHubAppUpgrade(base({
    replicas: [
      replica({ observedAt: "2026-08-25T02:00:00.000Z" }),
      replica({ replicaId: "synsec-0" }),
      replica({ replicaId: "synsec-extra" }),
    ],
  }));
  assert.equal(result.readyToBeginRollout, false);
  assert.equal(result.readyToFinalizeRollout, false);
  assert.ok(result.issues.some((issue) => issue.code === "stale-observation"));
  assert.ok(result.issues.some((issue) => issue.code === "duplicate-replica"));
  assert.ok(result.issues.some((issue) => issue.code === "unexpected-replica"));
  assert.ok(result.issues.some((issue) => issue.code === "missing-replica" && issue.replicaId === "synsec-1"));
});

test("target replicas reporting the wrong schema cannot finalize", () => {
  const result = assessSynSecGitHubAppUpgrade(base({
    targetSchemaVersion: 2,
    replicas: [
      replica({ releaseId: "0.2.0-new", schemaVersion: 1 }),
      replica({ replicaId: "synsec-1", releaseId: "0.2.0-new", schemaVersion: 2 }),
    ],
  }));
  assert.equal(result.readyToFinalizeRollout, false);
  assert.ok(result.issues.some((issue) => issue.code === "target-schema-mismatch" && issue.replicaId === "synsec-0"));
});

test("assessment output is secret-free categorical metadata", () => {
  const result = assessSynSecGitHubAppUpgrade(base({ previousReleaseAvailable: false }));
  const serialized = JSON.stringify(result);
  assert.doesNotMatch(serialized, /private.?key|webhook|postgresql:\/\//i);
  assert.ok(result.issues.some((issue) => issue.code === "previous-release-unavailable"));
});
