import assert from "node:assert/strict";
import test from "node:test";
import { assessLifecycleReviewDeadlines } from "@synsec/lifecycle/review-deadlines";

function store(records) {
  return { schemaVersion: 1, records };
}

function record(fingerprint, state, reviewAt) {
  return {
    fingerprint,
    state,
    updatedAt: "2026-08-01T00:00:00.000Z",
    ...(reviewAt ? { reviewAt } : {}),
  };
}

test("review deadline assessment separates overdue, soon-due, scheduled, and unscheduled exceptions", () => {
  const result = assessLifecycleReviewDeadlines(store({
    overdue: record("overdue", "accepted-risk", "2026-08-22T00:00:00.000Z"),
    soon: record("soon", "false-positive", "2026-08-25T00:00:00.000Z"),
    later: record("later", "accepted-risk", "2026-09-30T00:00:00.000Z"),
    unscheduled: record("unscheduled", "false-positive"),
    confirmed: record("confirmed", "confirmed", "2026-08-22T00:00:00.000Z"),
  }), {
    now: "2026-08-23T00:00:00.000Z",
    dueSoonWindowMs: 7 * 24 * 60 * 60 * 1000,
  });

  assert.deepEqual(result.summary, {
    reviewable: 4,
    unscheduled: 1,
    overdue: 1,
    dueSoon: 1,
    scheduled: 1,
  });
  assert.deepEqual(result.items.map(({ fingerprint, status }) => ({ fingerprint, status })), [
    { fingerprint: "overdue", status: "overdue" },
    { fingerprint: "soon", status: "due-soon" },
    { fingerprint: "later", status: "scheduled" },
  ]);
  assert.equal(result.generatedAt, "2026-08-23T00:00:00.000Z");
});

test("review deadline assessment is deterministic for equal deadlines", () => {
  const result = assessLifecycleReviewDeadlines(store({
    z: record("z", "accepted-risk", "2026-08-24T00:00:00.000Z"),
    a: record("a", "false-positive", "2026-08-24T00:00:00.000Z"),
  }), { now: "2026-08-23T00:00:00.000Z" });
  assert.deepEqual(result.items.map((item) => item.fingerprint), ["a", "z"]);
});

test("review deadline assessment excludes triage notes and ownership metadata", () => {
  const input = store({
    fp: {
      ...record("fp", "accepted-risk", "2026-08-24T00:00:00.000Z"),
      note: "secret-bearing human note must not be copied",
      owner: "security-team",
      reportId: "report-1",
      lastSeenPath: "private/internal.ts",
    },
  });
  const result = assessLifecycleReviewDeadlines(input, { now: "2026-08-23T00:00:00.000Z" });
  const serialized = JSON.stringify(result);
  assert.doesNotMatch(serialized, /secret-bearing|security-team|report-1|private\/internal/);
});

test("review deadline assessment rejects invalid clocks and windows", () => {
  const input = store({});
  assert.throws(() => assessLifecycleReviewDeadlines(input, { now: "not-a-time" }), /valid timestamp/);
  for (const dueSoonWindowMs of [-1, 1.5, 366 * 24 * 60 * 60 * 1000]) {
    assert.throws(() => assessLifecycleReviewDeadlines(input, { dueSoonWindowMs }), /due-soon window/);
  }
});
