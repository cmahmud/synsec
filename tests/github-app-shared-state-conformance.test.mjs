import assert from "node:assert/strict";
import test from "node:test";
import {
  GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS,
  assessGitHubAppSharedStateConformanceCoverage,
} from "@synsec/github/shared-state-conformance";
import { REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES } from "@synsec/github/app-deployment";

test("conformance matrix covers every required shared-state capability exactly once", () => {
  assert.deepEqual(
    GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.map((scenario) => scenario.capability),
    [...REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES],
  );
  assert.equal(
    new Set(GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.map((scenario) => scenario.id)).size,
    GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.length,
  );
});

test("complete scenario coverage is reported deterministically", () => {
  const ids = GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.map((scenario) => scenario.id).reverse();
  const assessment = assessGitHubAppSharedStateConformanceCoverage(ids);
  assert.equal(assessment.complete, true);
  assert.deepEqual(assessment.missingScenarioIds, []);
  assert.deepEqual(assessment.missingCapabilities, []);
  assert.deepEqual(assessment.coveredScenarioIds, GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.map((scenario) => scenario.id));
});

test("missing scenarios map back to the exact missing capability", () => {
  const missing = GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS[3];
  const ids = GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS
    .filter((scenario) => scenario.id !== missing.id)
    .map((scenario) => scenario.id);
  const assessment = assessGitHubAppSharedStateConformanceCoverage(ids);
  assert.equal(assessment.complete, false);
  assert.deepEqual(assessment.missingScenarioIds, [missing.id]);
  assert.deepEqual(assessment.missingCapabilities, [missing.capability]);
});

test("unknown and duplicate scenario ids cannot manufacture coverage", () => {
  const first = GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS[0];
  const assessment = assessGitHubAppSharedStateConformanceCoverage([
    first.id,
    first.id,
    "made-up.passes-anyway",
  ]);
  assert.equal(assessment.complete, false);
  assert.deepEqual(assessment.coveredScenarioIds, [first.id]);
  assert.equal(assessment.missingScenarioIds.length, GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.length - 1);
});
