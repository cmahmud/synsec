import assert from "node:assert/strict";
import test from "node:test";
import {
  runGitHubAppSharedStateConformance,
} from "@synsec/github/shared-state-conformance-runner";
import {
  GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS,
} from "@synsec/github/shared-state-conformance";

function createPassingAdapter(overrides = {}) {
  const calls = [];
  const scenarios = Object.fromEntries(
    GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.map(({ id }) => [
      id,
      async () => {
        calls.push(id);
      },
    ]),
  );
  Object.assign(scenarios, overrides);
  return {
    calls,
    adapter: {
      async reset() {
        calls.push("reset");
      },
      scenarios,
    },
  };
}

test("shared-state conformance runner executes the canonical matrix in stable order", async () => {
  const { adapter, calls } = createPassingAdapter();
  let clock = 0;
  const report = await runGitHubAppSharedStateConformance(adapter, {
    now: () => ++clock,
  });

  assert.equal(report.schemaVersion, 1);
  assert.equal(report.complete, true);
  assert.equal(report.results.length, GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.length);
  assert.deepEqual(
    report.results.map(({ id, status }) => [id, status]),
    GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.map(({ id }) => [id, "passed"]),
  );
  assert.deepEqual(
    calls,
    GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.flatMap(({ id }) => ["reset", id]),
  );
  assert.equal(report.coverage.complete, true);
  assert.deepEqual(report.coverage.missingScenarioIds, []);
});

test("shared-state conformance runner fails closed without exposing adapter errors", async () => {
  const failedId = GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS[2].id;
  const secret = "postgres://synsec:very-secret-password@db.internal/synsec";
  const { adapter } = createPassingAdapter({
    [failedId]: async () => {
      throw new Error(`database failed at ${secret}`);
    },
  });

  const report = await runGitHubAppSharedStateConformance(adapter);
  assert.equal(report.complete, false);
  assert.equal(report.results.find((result) => result.id === failedId)?.status, "failed");
  assert.deepEqual(report.coverage.missingScenarioIds, [failedId]);
  assert.equal(JSON.stringify(report).includes(secret), false);
  assert.equal(JSON.stringify(report).includes("db.internal"), false);
});

test("shared-state conformance runner treats reset failure as scenario failure and continues", async () => {
  const { adapter, calls } = createPassingAdapter();
  let resetCount = 0;
  adapter.reset = async () => {
    calls.push("reset");
    resetCount += 1;
    if (resetCount === 2) throw new Error("reset failed");
  };

  const report = await runGitHubAppSharedStateConformance(adapter);
  assert.equal(report.complete, false);
  assert.equal(report.results[1].status, "failed");
  assert.equal(report.results[2].status, "passed");
  assert.equal(resetCount, GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.length);
});

test("shared-state conformance runner times out a hung scenario and continues", async () => {
  const timedOutId = GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS[0].id;
  const { adapter } = createPassingAdapter({
    [timedOutId]: () => new Promise(() => {}),
  });

  const report = await runGitHubAppSharedStateConformance(adapter, { scenarioTimeoutMs: 100 });
  assert.equal(report.complete, false);
  assert.equal(report.results[0].status, "timed-out");
  assert.equal(report.results[1].status, "passed");
});

test("shared-state conformance runner rejects incomplete or expanded scenario maps", async () => {
  const { adapter } = createPassingAdapter();
  const missingId = GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS[0].id;
  delete adapter.scenarios[missingId];
  await assert.rejects(
    runGitHubAppSharedStateConformance(adapter),
    /must implement exactly the required scenario ids/,
  );

  const { adapter: expanded } = createPassingAdapter();
  expanded.scenarios["queue.magic-lock"] = async () => {};
  await assert.rejects(
    runGitHubAppSharedStateConformance(expanded),
    /must implement exactly the required scenario ids/,
  );
});

test("shared-state conformance runner bounds per-scenario timeouts", async () => {
  const { adapter } = createPassingAdapter();
  await assert.rejects(runGitHubAppSharedStateConformance(adapter, { scenarioTimeoutMs: 99 }), /between 100 and 120000/);
  await assert.rejects(runGitHubAppSharedStateConformance(adapter, { scenarioTimeoutMs: 120001 }), /between 100 and 120000/);
  await assert.rejects(runGitHubAppSharedStateConformance(adapter, { scenarioTimeoutMs: 1.5 }), /between 100 and 120000/);
});
