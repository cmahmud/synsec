import assert from "node:assert/strict";
import test from "node:test";
import { evaluateLifecycleReviewPolicy } from "@synsec/lifecycle/review-policy";

function assessment(summary, generatedAt = "2026-08-23T00:00:00.000Z") {
  return {
    schemaVersion: 1,
    generatedAt,
    dueSoonWindowMs: 7 * 24 * 60 * 60 * 1000,
    items: [
      {
        fingerprint: "sensitive-fingerprint",
        state: "accepted-risk",
        reviewAt: "2026-08-22T00:00:00.000Z",
        status: "overdue",
      },
    ],
    summary,
  };
}

test("review policy reports deterministic aggregate violations without finding identifiers", () => {
  const result = evaluateLifecycleReviewPolicy(assessment({
    reviewable: 4,
    overdue: 1,
    dueSoon: 1,
    scheduled: 1,
    unscheduled: 1,
  }), {
    failOnOverdue: true,
    failOnUnscheduled: true,
  });

  assert.deepEqual(result, {
    schemaVersion: 1,
    generatedAt: "2026-08-23T00:00:00.000Z",
    ready: false,
    violations: ["overdue", "unscheduled"],
    summary: {
      reviewable: 4,
      overdue: 1,
      dueSoon: 1,
      scheduled: 1,
      unscheduled: 1,
    },
  });
  assert.doesNotMatch(JSON.stringify(result), /sensitive-fingerprint|2026-08-22/);
});

test("review policy passes when configured policy has no violations", () => {
  const result = evaluateLifecycleReviewPolicy(assessment({
    reviewable: 2,
    overdue: 0,
    dueSoon: 1,
    scheduled: 1,
    unscheduled: 0,
  }), {
    failOnOverdue: true,
    failOnUnscheduled: true,
  });
  assert.equal(result.ready, true);
  assert.deepEqual(result.violations, []);
});

test("review policy validates assessment summary consistency", () => {
  assert.throws(() => evaluateLifecycleReviewPolicy(assessment({
    reviewable: 2,
    overdue: 1,
    dueSoon: 0,
    scheduled: 0,
    unscheduled: 0,
  })), /internally inconsistent/);

  assert.throws(() => evaluateLifecycleReviewPolicy(assessment({
    reviewable: 1,
    overdue: -1,
    dueSoon: 0,
    scheduled: 1,
    unscheduled: 1,
  })), /invalid overdue count/);
});
