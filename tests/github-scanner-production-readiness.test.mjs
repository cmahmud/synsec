import assert from "node:assert/strict";
import test from "node:test";
import {
  assessGitHubAppScannerProductionReadiness,
  assertGitHubAppScannerProductionReady,
} from "@synsec/github/scanner-production-readiness";

const deployment = {
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

const scannerIsolationProfile = {
  schemaVersion: 1,
  runtime: "container",
  cpuLimit: true,
  memoryLimit: true,
  networkPolicy: "none",
  repositoryReadOnly: true,
  rootFilesystemReadOnly: true,
  scratchSeparated: true,
  credentialsExcluded: true,
  durableStateExcluded: true,
  privileged: false,
  allowPrivilegeEscalation: false,
  runAsNonRoot: true,
  capabilitiesDropped: true,
  hostNetwork: false,
  hostPid: false,
  hostIpc: false,
  hostSocketMounts: false,
};

test("scanner production readiness requires both deployment and detailed isolation declarations", () => {
  const result = assessGitHubAppScannerProductionReadiness({ deployment, scannerIsolationProfile });
  assert.equal(result.ready, true);
  assert.equal(result.deployment.ready, true);
  assert.equal(result.scannerIsolation.complete, true);
  assert.equal(result.interpretation, "deployment-and-isolation-declarations-not-runtime-certification");
  assert.doesNotThrow(() => assertGitHubAppScannerProductionReady({ deployment, scannerIsolationProfile }));
});

test("scanner production readiness forces strict deployment isolation even when caller leaves it advisory", () => {
  const { scannerIsolation, ...unisolatedDeployment } = deployment;
  const result = assessGitHubAppScannerProductionReadiness({
    deployment: unisolatedDeployment,
    scannerIsolationProfile,
  });
  assert.equal(result.ready, false);
  assert.ok(result.deployment.issues.some((issue) =>
    issue.level === "error" && issue.code === "scanner-isolation-missing"));
});

test("scanner production readiness fails when the detailed profile exposes a container escape surface", () => {
  const result = assessGitHubAppScannerProductionReadiness({
    deployment,
    scannerIsolationProfile: {
      ...scannerIsolationProfile,
      privileged: true,
      allowPrivilegeEscalation: true,
      capabilitiesDropped: false,
      hostSocketMounts: true,
    },
  });
  assert.equal(result.ready, false);
  assert.deepEqual(result.scannerIsolation.missing, [
    "not-privileged",
    "no-privilege-escalation",
    "capabilities-dropped",
    "no-host-socket-mounts",
  ]);
  assert.throws(
    () => assertGitHubAppScannerProductionReady({
      deployment,
      scannerIsolationProfile: {
        ...scannerIsolationProfile,
        privileged: true,
        allowPrivilegeEscalation: true,
        capabilitiesDropped: false,
        hostSocketMounts: true,
      },
    }),
    /scanner-isolation:not-privileged, scanner-isolation:no-privilege-escalation, scanner-isolation:capabilities-dropped, scanner-isolation:no-host-socket-mounts/,
  );
});

test("scanner production readiness assertion reports codes instead of credential values", () => {
  const secret = "must-not-appear";
  assert.throws(
    () => assertGitHubAppScannerProductionReady({
      deployment: { ...deployment, webhookSecret: secret },
      scannerIsolationProfile,
    }),
    (error) => {
      assert.match(error.message, /deployment:weak-webhook-secret/);
      assert.doesNotMatch(error.message, new RegExp(secret));
      return true;
    },
  );
});
