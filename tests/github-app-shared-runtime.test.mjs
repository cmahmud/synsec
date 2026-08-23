import assert from "node:assert/strict";
import test from "node:test";
import { createGitHubAppSharedRuntime } from "@synsec/github/shared-runtime";
import {
  GITHUB_APP_SHARED_STATE_CONTRACT_VERSION,
} from "@synsec/github/shared-state-contract";
import { REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES } from "@synsec/github/app-deployment";
import { GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS } from "@synsec/github/shared-state-conformance";

function contract() {
  return {
    contractVersion: GITHUB_APP_SHARED_STATE_CONTRACT_VERSION,
    backendId: "postgres-v1",
    implementationVersion: "0.2.0",
    capabilities: Object.fromEntries(REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES.map((capability) => [capability, true])),
    evidence: REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES.map((capability) => ({
      capability,
      mechanism: "serializable-transaction",
      reference: `conformance-${capability}`,
    })),
  };
}

function conformanceReport(overrides = {}) {
  const coveredScenarioIds = GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.map((scenario) => scenario.id);
  return {
    schemaVersion: 1,
    backendId: "postgres-v1",
    implementationVersion: "0.2.0",
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

function stores() {
  return {
    replayStore: {
      claim: async () => true,
      release: async () => true,
    },
    installationStore: {
      get: async () => undefined,
      put: async (record) => record,
      remove: async () => false,
      isRepositoryAllowed: async () => true,
    },
    queue: {
      enqueue: async (job) => ({ ...job, version: 1, jobId: "0".repeat(32), createdAt: new Date(0).toISOString(), attempts: 0, status: "pending" }),
      claimNext: async () => undefined,
      assertLease: async () => { throw new Error("not called"); },
      release: async () => { throw new Error("not called"); },
      fail: async () => { throw new Error("not called"); },
      complete: async () => false,
    },
  };
}

function worker() {
  return {
    config: { schemaVersion: 1, scanners: {} },
    getInstallationToken: async () => "unused",
  };
}

test("composes shared stores only behind complete identity-bound conformance evidence", () => {
  const backendContract = contract();
  const state = stores();
  const runtime = createGitHubAppSharedRuntime({
    backendContract,
    conformanceReport: conformanceReport(),
    webhookSecret: "s".repeat(32),
    ...state,
    worker: worker(),
  });
  assert.equal(runtime.backendId, "postgres-v1");
  assert.equal(runtime.implementationVersion, "0.2.0");
  assert.equal(typeof runtime.webhookHandler, "function");
  assert.equal(typeof runtime.runWorkerOnce, "function");
});

test("rejects incomplete backend evidence before composing external stores", () => {
  const backendContract = contract();
  backendContract.evidence.pop();
  const state = stores();
  assert.throws(() => createGitHubAppSharedRuntime({
    backendContract,
    conformanceReport: conformanceReport(),
    webhookSecret: "s".repeat(32),
    ...state,
    worker: worker(),
  }), /invalid-backend-contract/);
});

test("rejects unversioned or unknown-field backend declarations", () => {
  const backendContract = { ...contract(), connectionString: "not-accepted" };
  const state = stores();
  assert.throws(() => createGitHubAppSharedRuntime({
    backendContract,
    conformanceReport: conformanceReport(),
    webhookSecret: "s".repeat(32),
    ...state,
    worker: worker(),
  }), /invalid-backend-contract/);
});

test("rejects stale or missing conformance evidence before stores become active", () => {
  const state = stores();
  assert.throws(() => createGitHubAppSharedRuntime({
    backendContract: contract(),
    conformanceReport: conformanceReport({ implementationVersion: "0.1.9" }),
    webhookSecret: "s".repeat(32),
    ...state,
    worker: worker(),
  }), /implementation-version-mismatch/);

  assert.throws(() => createGitHubAppSharedRuntime({
    backendContract: contract(),
    conformanceReport: undefined,
    webhookSecret: "s".repeat(32),
    ...state,
    worker: worker(),
  }), /invalid-conformance-report/);
});
