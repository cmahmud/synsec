import assert from "node:assert/strict";
import test from "node:test";
import {
  GITHUB_APP_SHARED_STATE_CONTRACT_VERSION,
  assessGitHubAppSharedStateBackendContract,
  assertGitHubAppSharedStateBackendContract,
} from "@synsec/github/shared-state-contract";
import { REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES } from "@synsec/github/app-deployment";

function completeContract() {
  return {
    contractVersion: GITHUB_APP_SHARED_STATE_CONTRACT_VERSION,
    backendId: "postgres-v1",
    implementationVersion: "0.2.0",
    capabilities: Object.fromEntries(REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES.map((capability) => [capability, true])),
    evidence: REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES.map((capability) => ({
      capability,
      mechanism: capability === "compareAndSetLeaseRenewal" ? "compare-and-set" : capability === "fencedQueueTransitions" ? "fencing-token" : "serializable-transaction",
      reference: `conformance-${capability}`,
    })),
  };
}

test("accepts one complete versioned backend contract", () => {
  const contract = completeContract();
  const assessment = assessGitHubAppSharedStateBackendContract(contract);
  assert.equal(assessment.ready, true);
  assert.deepEqual(assessment.issues, []);
  assert.deepEqual(assessment.missingEvidence, []);
  assert.doesNotThrow(() => assertGitHubAppSharedStateBackendContract(contract));
});

test("requires implementation evidence for every transactional capability", () => {
  const contract = completeContract();
  contract.evidence = contract.evidence.filter((entry) => entry.capability !== "atomicReplayClaim");
  const assessment = assessGitHubAppSharedStateBackendContract(contract);
  assert.equal(assessment.ready, false);
  assert.deepEqual(assessment.missingEvidence, ["atomicReplayClaim"]);
  assert.ok(assessment.issues.some((issue) => issue.code === "missing-capability-evidence" && issue.capability === "atomicReplayClaim"));
});

test("rejects duplicate capability evidence instead of counting it twice", () => {
  const contract = completeContract();
  contract.evidence[1] = { ...contract.evidence[0] };
  const assessment = assessGitHubAppSharedStateBackendContract(contract);
  assert.equal(assessment.ready, false);
  assert.ok(assessment.issues.some((issue) => issue.code === "duplicate-evidence"));
  assert.ok(assessment.missingEvidence.length >= 1);
});

test("rejects false or incomplete capability declarations", () => {
  const contract = completeContract();
  contract.capabilities.atomicQueueInsertion = false;
  const assessment = assessGitHubAppSharedStateBackendContract(contract);
  assert.equal(assessment.ready, false);
  assert.ok(assessment.issues.some((issue) => issue.code === "invalid-capabilities"));
});

test("rejects credential-like or outbound evidence references", () => {
  const contract = completeContract();
  contract.evidence[0].reference = "postgres://user:password@db.example/internal";
  const assessment = assessGitHubAppSharedStateBackendContract(contract);
  assert.equal(assessment.ready, false);
  assert.ok(assessment.issues.some((issue) => issue.code === "invalid-evidence"));
});

test("rejects unknown fields and unsupported contract versions", () => {
  const withUnknownField = { ...completeContract(), connectionString: "should-not-be-accepted" };
  assert.deepEqual(assessGitHubAppSharedStateBackendContract(withUnknownField).issues.map((issue) => issue.code), ["invalid-shape"]);

  const wrongVersion = completeContract();
  wrongVersion.contractVersion = 2;
  const assessment = assessGitHubAppSharedStateBackendContract(wrongVersion);
  assert.equal(assessment.ready, false);
  assert.ok(assessment.issues.some((issue) => issue.code === "unsupported-contract-version"));
});
