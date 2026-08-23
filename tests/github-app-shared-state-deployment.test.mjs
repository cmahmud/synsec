import assert from "node:assert/strict";
import test from "node:test";
import {
  assessGitHubAppSharedStateCapabilities,
  REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES,
  validateGitHubAppDeployment,
} from "@synsec/github/app-deployment";

const validConfig = {
  appId: 12345,
  privateKey: "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----",
  webhookSecret: "a".repeat(32),
  listenHost: "0.0.0.0",
  tlsMode: "terminated-upstream",
  stateDirectory: "/var/lib/synsec/state",
  workspaceDirectory: "/var/lib/synsec/workspaces",
  scannerIsolation: {
    processBoundary: "container",
    cpuLimit: true,
    memoryLimit: true,
    networkPolicy: "none",
    repositoryFilesystem: "read-only",
  },
};

const completeCapabilities = {
  atomicReplayClaim: true,
  atomicQueueInsertion: true,
  atomicQueueClaimWithFence: true,
  compareAndSetLeaseRenewal: true,
  fencedQueueTransitions: true,
  transactionalInstallationState: true,
  sharedAuthorizationState: true,
};

test("single-replica deployments retain the built-in filesystem state contract", () => {
  for (const replicaCount of [undefined, 1]) {
    const result = validateGitHubAppDeployment({ ...validConfig, replicaCount });
    assert.equal(result.ready, true);
    assert.equal(result.issues.some((issue) => issue.code.startsWith("shared-state")), false);
  }
});

test("multi-replica deployments fail closed on filesystem state", () => {
  for (const stateBackend of [undefined, { kind: "filesystem" }]) {
    const result = validateGitHubAppDeployment({
      ...validConfig,
      replicaCount: 2,
      stateBackend,
    });
    assert.equal(result.ready, false);
    assert.deepEqual(
      result.issues.filter((issue) => issue.code.startsWith("shared-state")).map((issue) => issue.code),
      ["shared-state-required"],
    );
  }
});

test("shared-state capability assessment is deterministic and complete", () => {
  assert.deepEqual(
    REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES,
    Object.keys(completeCapabilities),
  );
  assert.deepEqual(assessGitHubAppSharedStateCapabilities(completeCapabilities), {
    complete: true,
    missing: [],
  });
  assert.deepEqual(assessGitHubAppSharedStateCapabilities(undefined), {
    complete: false,
    missing: [...REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES],
  });
});

test("multi-replica deployments identify every missing transactional state guarantee", () => {
  for (const missingCapability of Object.keys(completeCapabilities)) {
    const capabilities = { ...completeCapabilities, [missingCapability]: false };
    const result = validateGitHubAppDeployment({
      ...validConfig,
      replicaCount: 3,
      stateBackend: { kind: "shared-transactional", capabilities },
    });
    assert.equal(result.ready, false, missingCapability);
    const issue = result.issues.find((candidate) => candidate.code === "shared-state-capabilities-incomplete");
    assert.ok(issue, missingCapability);
    assert.deepEqual(issue.missingCapabilities, [missingCapability], missingCapability);
    assert.equal(issue.message.includes(missingCapability), false, "human message should not require identifier parsing");
  }
});

test("shared-state readiness returns all missing capabilities in stable contract order", () => {
  const capabilities = {
    ...completeCapabilities,
    atomicQueueInsertion: false,
    compareAndSetLeaseRenewal: false,
    sharedAuthorizationState: false,
  };
  const assessment = assessGitHubAppSharedStateCapabilities(capabilities);
  assert.deepEqual(assessment, {
    complete: false,
    missing: ["atomicQueueInsertion", "compareAndSetLeaseRenewal", "sharedAuthorizationState"],
  });

  const result = validateGitHubAppDeployment({
    ...validConfig,
    replicaCount: 4,
    stateBackend: { kind: "shared-transactional", capabilities },
  });
  const issue = result.issues.find((candidate) => candidate.code === "shared-state-capabilities-incomplete");
  assert.ok(issue);
  assert.deepEqual(issue.missingCapabilities, assessment.missing);
});

test("a complete shared transactional contract permits multiple replicas", () => {
  const result = validateGitHubAppDeployment({
    ...validConfig,
    replicaCount: 8,
    stateBackend: { kind: "shared-transactional", capabilities: completeCapabilities },
  });
  assert.equal(result.ready, true);
  assert.deepEqual(result.issues, []);
});

test("replica count is bounded before shared-state evaluation", () => {
  for (const replicaCount of [0, -1, 1.5, Number.NaN, 1001]) {
    const result = validateGitHubAppDeployment({
      ...validConfig,
      replicaCount,
      stateBackend: { kind: "shared-transactional", capabilities: completeCapabilities },
    });
    assert.equal(result.ready, false);
    assert.ok(result.issues.some((issue) => issue.code === "invalid-replica-count"));
    assert.equal(result.issues.some((issue) => issue.code.startsWith("shared-state")), false);
  }
});
