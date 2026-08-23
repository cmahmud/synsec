import assert from "node:assert/strict";
import test from "node:test";
import {
  REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES,
} from "@synsec/github/app-deployment";
import {
  runGitHubAppSharedStateConformance,
} from "@synsec/github/shared-state-conformance-runner";
import {
  GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS,
} from "@synsec/github/shared-state-conformance";
import {
  assessGitHubAppSharedStateConformanceEvidence,
} from "@synsec/github/shared-state-evidence";

function createContract(overrides = {}) {
  return {
    contractVersion: 1,
    backendId: "postgres-v1",
    implementationVersion: "0.2.0-build.42",
    capabilities: Object.fromEntries(REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES.map((capability) => [capability, true])),
    evidence: REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES.map((capability) => ({
      capability,
      mechanism: "shared-durable-store",
      reference: `conformance-${capability}`,
    })),
    ...overrides,
  };
}

async function createReport(overrides = {}) {
  const scenarios = Object.fromEntries(
    GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.map(({ id }) => [id, async () => {}]),
  );
  return runGitHubAppSharedStateConformance({
    backendId: "postgres-v1",
    implementationVersion: "0.2.0-build.42",
    async reset() {},
    scenarios,
    ...overrides,
  });
}

test("shared-state evidence gate accepts complete identity-bound evidence", async () => {
  const report = await createReport();
  const assessment = assessGitHubAppSharedStateConformanceEvidence(createContract(), report);

  assert.equal(assessment.ready, true);
  assert.deepEqual(assessment.issues, []);
  assert.equal(assessment.passedScenarioIds.length, GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.length);
  assert.deepEqual(assessment.missingScenarioIds, []);
});

test("shared-state evidence gate rejects backend and implementation identity mismatch", async () => {
  const report = await createReport();
  const assessment = assessGitHubAppSharedStateConformanceEvidence(
    createContract({ backendId: "cockroach-v1", implementationVersion: "0.2.1" }),
    report,
  );

  assert.equal(assessment.ready, false);
  assert.deepEqual(
    assessment.issues.map((issue) => issue.code),
    ["backend-id-mismatch", "implementation-version-mismatch"],
  );
});

test("shared-state evidence gate recomputes scenario truth instead of trusting complete", async () => {
  const report = await createReport();
  const failedId = GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS[0].id;
  report.results[0].status = "failed";
  report.complete = true;

  const assessment = assessGitHubAppSharedStateConformanceEvidence(createContract(), report);
  assert.equal(assessment.ready, false);
  assert.deepEqual(assessment.issues.map((issue) => issue.code), ["invalid-conformance-report"]);
  assert.deepEqual(
    assessment.missingScenarioIds,
    GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.map((scenario) => scenario.id),
  );
  assert.equal(assessment.passedScenarioIds.includes(failedId), false);
});

test("shared-state evidence gate rejects tampered derived coverage", async () => {
  const report = await createReport();
  report.coverage.coveredScenarioIds = [];
  report.coverage.missingScenarioIds = ["replay.concurrent-duplicate-claim"];

  const assessment = assessGitHubAppSharedStateConformanceEvidence(createContract(), report);
  assert.equal(assessment.ready, false);
  assert.deepEqual(assessment.issues.map((issue) => issue.code), ["invalid-conformance-report"]);
});

test("shared-state evidence gate rejects incomplete but structurally honest report", async () => {
  const failedId = GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS[3].id;
  const report = await createReport({
    scenarios: Object.fromEntries(
      GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.map(({ id }) => [
        id,
        id === failedId ? async () => { throw new Error("expected test failure"); } : async () => {},
      ]),
    ),
  });

  const assessment = assessGitHubAppSharedStateConformanceEvidence(createContract(), report);
  assert.equal(assessment.ready, false);
  assert.deepEqual(assessment.issues.map((issue) => issue.code), ["incomplete-conformance"]);
  assert.deepEqual(assessment.missingScenarioIds, [failedId]);
});

test("shared-state evidence gate rejects duplicate, unknown, or malformed scenario results", async () => {
  const report = await createReport();
  report.results[1] = { ...report.results[0] };
  let assessment = assessGitHubAppSharedStateConformanceEvidence(createContract(), report);
  assert.deepEqual(assessment.issues.map((issue) => issue.code), ["invalid-conformance-report"]);

  const unknown = await createReport();
  unknown.results[0].id = "queue.invented-proof";
  assessment = assessGitHubAppSharedStateConformanceEvidence(createContract(), unknown);
  assert.deepEqual(assessment.issues.map((issue) => issue.code), ["invalid-conformance-report"]);
});

test("shared-state evidence gate rejects invalid backend contract without echoing values", async () => {
  const report = await createReport();
  const secret = "postgres://user:secret@db.internal/synsec";
  const assessment = assessGitHubAppSharedStateConformanceEvidence(
    createContract({ backendId: secret }),
    report,
  );

  assert.equal(assessment.ready, false);
  assert.equal(assessment.issues[0].code, "invalid-backend-contract");
  assert.equal(JSON.stringify(assessment).includes(secret), false);
  assert.equal(JSON.stringify(assessment).includes("db.internal"), false);
});
