import assert from "node:assert/strict";
import test from "node:test";
import {
  assertGitHubAppDeploymentReady,
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

test("hosted deployment readiness accepts separated state, TLS termination, and declared scanner isolation", () => {
  const result = validateGitHubAppDeployment(validConfig);
  assert.equal(result.ready, true);
  assert.deepEqual(result.issues, []);
  assert.doesNotThrow(() => assertGitHubAppDeploymentReady(validConfig));
});

test("scanner isolation is warning-only by default but can be required for production startup", () => {
  const { scannerIsolation, ...withoutIsolation } = validConfig;
  const advisory = validateGitHubAppDeployment(withoutIsolation);
  assert.equal(advisory.ready, true);
  assert.deepEqual(advisory.issues.map((issue) => [issue.level, issue.code]), [
    ["warning", "scanner-isolation-missing"],
  ]);

  const strict = validateGitHubAppDeployment({ ...withoutIsolation, requireScannerIsolation: true });
  assert.equal(strict.ready, false);
  assert.deepEqual(strict.issues.map((issue) => [issue.level, issue.code]), [
    ["error", "scanner-isolation-missing"],
  ]);
  assert.throws(() => assertGitHubAppDeploymentReady({ ...withoutIsolation, requireScannerIsolation: true }), /scanner-isolation-missing/);
});

test("strict scanner isolation rejects host execution, missing resources, host networking, and writable source", () => {
  const result = validateGitHubAppDeployment({
    ...validConfig,
    requireScannerIsolation: true,
    scannerIsolation: {
      processBoundary: "host",
      cpuLimit: false,
      memoryLimit: false,
      networkPolicy: "host",
      repositoryFilesystem: "writable",
    },
  });
  assert.equal(result.ready, false);
  assert.deepEqual(new Set(result.issues.map((issue) => issue.code)), new Set([
    "scanner-process-unisolated",
    "scanner-resource-limits-missing",
    "scanner-network-unrestricted",
    "scanner-repository-writable",
  ]));
  assert.equal(result.issues.every((issue) => issue.level === "error"), true);
});

test("egress-filtered sandbox execution satisfies the isolation contract", () => {
  const result = validateGitHubAppDeployment({
    ...validConfig,
    requireScannerIsolation: true,
    scannerIsolation: {
      processBoundary: "sandbox",
      cpuLimit: true,
      memoryLimit: true,
      networkPolicy: "egress-filtered",
      repositoryFilesystem: "read-only",
    },
  });
  assert.equal(result.ready, true);
  assert.deepEqual(result.issues, []);
});

test("hosted deployment readiness rejects a plaintext non-loopback listener", () => {
  const result = validateGitHubAppDeployment({ ...validConfig, tlsMode: "none" });
  assert.equal(result.ready, false);
  assert.ok(result.issues.some((issue) => issue.code === "plaintext-public-listener"));
});

test("hosted deployment readiness permits plaintext loopback for local development", () => {
  const result = validateGitHubAppDeployment({
    ...validConfig,
    listenHost: "127.0.0.1",
    tlsMode: "none",
  });
  assert.equal(result.ready, true);
});

test("hosted deployment readiness rejects weak credentials without echoing them", () => {
  const privateKey = "not-a-private-key";
  const webhookSecret = "short-secret";
  const result = validateGitHubAppDeployment({
    ...validConfig,
    appId: 0,
    privateKey,
    webhookSecret,
  });

  assert.equal(result.ready, false);
  assert.deepEqual(
    new Set(result.issues.map((issue) => issue.code)),
    new Set(["invalid-app-id", "invalid-private-key", "weak-webhook-secret"]),
  );
  assert.ok(result.issues.every((issue) => !issue.message.includes(privateKey)));
  assert.ok(result.issues.every((issue) => !issue.message.includes(webhookSecret)));
});

test("hosted deployment readiness rejects mismatched PEM framing and wildcard listener values", () => {
  const mismatchedPem = validateGitHubAppDeployment({
    ...validConfig,
    privateKey: "-----BEGIN RSA PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----",
  });
  assert.equal(mismatchedPem.ready, false);
  assert.ok(mismatchedPem.issues.some((issue) => issue.code === "invalid-private-key"));

  const wildcardHost = validateGitHubAppDeployment({ ...validConfig, listenHost: "*" });
  assert.equal(wildcardHost.ready, false);
  assert.ok(wildcardHost.issues.some((issue) => issue.code === "invalid-listen-host"));
});

test("hosted deployment readiness rejects relative and overlapping runtime directories", () => {
  const relative = validateGitHubAppDeployment({
    ...validConfig,
    stateDirectory: "./state",
    workspaceDirectory: "./workspaces",
  });
  assert.equal(relative.ready, false);
  assert.ok(relative.issues.some((issue) => issue.code === "relative-state-directory"));
  assert.ok(relative.issues.some((issue) => issue.code === "relative-workspace-directory"));

  const nested = validateGitHubAppDeployment({
    ...validConfig,
    stateDirectory: "/var/lib/synsec",
    workspaceDirectory: "/var/lib/synsec/workspaces",
  });
  assert.equal(nested.ready, false);
  assert.ok(nested.issues.some((issue) => issue.code === "overlapping-runtime-directories"));
});

test("deployment assertion reports only bounded diagnostic codes", () => {
  assert.throws(
    () =>
      assertGitHubAppDeploymentReady({
        ...validConfig,
        webhookSecret: "must-not-appear",
        stateDirectory: "/srv/synsec",
        workspaceDirectory: "/srv/synsec/repos",
      }),
    (error) => {
      assert.match(error.message, /weak-webhook-secret/);
      assert.match(error.message, /overlapping-runtime-directories/);
      assert.doesNotMatch(error.message, /must-not-appear/);
      return true;
    },
  );
});
