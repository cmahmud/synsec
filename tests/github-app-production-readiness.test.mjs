import assert from "node:assert/strict";
import test from "node:test";
import {
  REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES,
} from "@synsec/github/app-deployment";
import {
  GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS,
} from "@synsec/github/shared-state-conformance";
import {
  assessGitHubAppProductionReadiness,
  assertGitHubAppProductionReady,
} from "@synsec/github/production-readiness";

const capabilities = Object.fromEntries(
  REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES.map((capability) => [capability, true]),
);

function deployment(overrides = {}) {
  return {
    appId: 123,
    privateKey: "-----BEGIN PRIVATE KEY-----\ntest-only\n-----END PRIVATE KEY-----",
    webhookSecret: "a".repeat(32),
    listenHost: "127.0.0.1",
    tlsMode: "none",
    stateDirectory: "/var/lib/synsec/state",
    workspaceDirectory: "/var/lib/synsec/workspaces",
    ...overrides,
  };
}

function contract(overrides = {}) {
  return {
    contractVersion: 1,
    backendId: "postgres-v1",
    implementationVersion: "build.42",
    capabilities,
    evidence: REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES.map((capability) => ({
      capability,
      mechanism: "shared-durable-store",
      reference: `conformance-${capability}`,
    })),
    ...overrides,
  };
}

function report(overrides = {}) {
  const coveredScenarioIds = GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.map((scenario) => scenario.id);
  return {
    schemaVersion: 1,
    backendId: "postgres-v1",
    implementationVersion: "build.42",
    complete: true,
    scenarioTimeoutMs: 5000,
    results: coveredScenarioIds.map((id) => ({ id, status: "passed", durationMs: 1 })),
    coverage: {
      complete: true,
      coveredScenarioIds,
      missingScenarioIds: [],
      missingCapabilities: [],
    },
    ...overrides,
  };
}

test("production readiness keeps single-replica deployments independent of shared-state evidence", () => {
  const readiness = assessGitHubAppProductionReadiness(deployment());
  assert.equal(readiness.ready, true);
  assert.equal(readiness.requiresSharedStateEvidence, false);
  assert.equal(readiness.sharedStateEvidence, undefined);
});

test("production readiness fails closed when multi-replica evidence is absent", () => {
  const readiness = assessGitHubAppProductionReadiness(deployment({
    replicaCount: 2,
    stateBackend: { kind: "shared-transactional", capabilities },
  }));

  assert.equal(readiness.deployment.ready, true);
  assert.equal(readiness.requiresSharedStateEvidence, true);
  assert.equal(readiness.ready, false);
  assert.deepEqual(
    readiness.sharedStateEvidence.issues.map((issue) => issue.code),
    ["invalid-backend-contract", "invalid-conformance-report"],
  );
});

test("production readiness accepts complete evidence for the exact multi-replica adapter build", () => {
  const readiness = assessGitHubAppProductionReadiness(
    deployment({ replicaCount: 3, stateBackend: { kind: "shared-transactional", capabilities } }),
    contract(),
    report(),
  );

  assert.equal(readiness.ready, true);
  assert.equal(readiness.deployment.ready, true);
  assert.equal(readiness.sharedStateEvidence.ready, true);
});

test("production readiness rejects stale conformance evidence despite complete capability declarations", () => {
  const readiness = assessGitHubAppProductionReadiness(
    deployment({ replicaCount: 2, stateBackend: { kind: "shared-transactional", capabilities } }),
    contract({ implementationVersion: "build.43" }),
    report(),
  );

  assert.equal(readiness.deployment.ready, true);
  assert.equal(readiness.ready, false);
  assert.deepEqual(
    readiness.sharedStateEvidence.issues.map((issue) => issue.code),
    ["implementation-version-mismatch"],
  );
});

test("production readiness assertion reports categorical codes without credential values", () => {
  const secret = "postgres://user:must-not-echo@db.internal/synsec";
  assert.throws(
    () => assertGitHubAppProductionReady(
      deployment({ replicaCount: 2, stateBackend: { kind: "shared-transactional", capabilities } }),
      contract({ backendId: secret }),
      report(),
    ),
    (error) => {
      assert.match(error.message, /invalid-backend-contract/);
      assert.doesNotMatch(error.message, /must-not-echo|db\.internal/);
      return true;
    },
  );
});
