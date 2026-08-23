import assert from "node:assert/strict";
import test from "node:test";
import { validateGitHubAppDeployment } from "@synsec/github/app-deployment";

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

test("multi-replica deployments require every transactional state guarantee", () => {
  for (const missingCapability of Object.keys(completeCapabilities)) {
    const capabilities = { ...completeCapabilities, [missingCapability]: false };
    const result = validateGitHubAppDeployment({
      ...validConfig,
      replicaCount: 3,
      stateBackend: { kind: "shared-transactional", capabilities },
    });
    assert.equal(result.ready, false, missingCapability);
    assert.ok(
      result.issues.some((issue) => issue.code === "shared-state-capabilities-incomplete"),
      missingCapability,
    );
  }
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
