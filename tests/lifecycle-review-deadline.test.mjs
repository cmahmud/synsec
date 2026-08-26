import assert from "node:assert/strict";
import test from "node:test";

import {
  emptyLifecycleStore,
  isLifecycleStore,
  reconcileLifecycle,
  setFindingReviewAt,
  setFindingState,
} from "@synsec/lifecycle";
import { buildFindingTriageView } from "@synsec/lifecycle/triage-view";
import { renderFindingTriageHtml } from "@synsec/lifecycle/triage-html";
import { emptyFindingReviewCommentStore } from "@synsec/lifecycle/review-comments";
import { buildReport } from "@synsec/report";

function report() {
  return buildReport({
    target: { path: "/repo" },
    scans: [{
      scanner: "fixture",
      startedAt: "2026-08-22T20:00:00.000Z",
      completedAt: "2026-08-22T20:00:01.000Z",
      target: { path: "/repo" },
      diagnostics: [],
      findings: [{
        id: "REVIEW-1",
        title: "Accepted risk needs periodic review",
        category: "sast",
        severity: "medium",
        confidence: 1,
        scanner: { name: "fixture", ruleId: "REVIEW-1" },
        location: { path: "src/app.ts", startLine: 7 },
      }],
    }],
    scope: { mode: "repository" },
  });
}

test("review deadlines are bounded human triage metadata preserved across reconciliation", () => {
  const current = report();
  const fingerprint = current.findings[0].fingerprint;
  let store = reconcileLifecycle(current, emptyLifecycleStore(), "2026-08-22T20:01:00.000Z");
  store = setFindingState(store, fingerprint, "accepted-risk", {
    note: "temporary vendor constraint",
    reviewAt: "2026-11-01T12:00:00.000Z",
    updatedAt: "2026-08-22T20:02:00.000Z",
  });
  assert.equal(store.records[fingerprint].reviewAt, "2026-11-01T12:00:00.000Z");

  const reconciled = reconcileLifecycle(current, store, "2026-08-23T20:00:00.000Z");
  assert.equal(reconciled.records[fingerprint].state, "accepted-risk");
  assert.equal(reconciled.records[fingerprint].reviewAt, "2026-11-01T12:00:00.000Z");
  assert.equal(reconciled.records[fingerprint].note, "temporary vendor constraint");

  const view = buildFindingTriageView(current, reconciled, emptyFindingReviewCommentStore());
  assert.equal(view.items[0].reviewAt, "2026-11-01T12:00:00.000Z");
  assert.equal(view.interpretation, "triage-metadata-not-scanner-evidence");
  assert.match(renderFindingTriageHtml(view), /Review by/);
  assert.match(renderFindingTriageHtml(view), /2026-11-01T12:00:00.000Z/);
});

test("review deadlines can be updated or cleared without changing finding state", () => {
  const current = report();
  const fingerprint = current.findings[0].fingerprint;
  let store = reconcileLifecycle(current, emptyLifecycleStore(), "2026-08-22T20:01:00.000Z");
  store = setFindingState(store, fingerprint, "accepted-risk", { updatedAt: "2026-08-22T20:02:00.000Z" });
  store = setFindingReviewAt(store, fingerprint, "2026-12-01T00:00:00.000Z", "2026-08-22T20:03:00.000Z");
  assert.equal(store.records[fingerprint].state, "accepted-risk");
  assert.equal(store.records[fingerprint].reviewAt, "2026-12-01T00:00:00.000Z");

  store = setFindingReviewAt(store, fingerprint, null, "2026-08-22T20:04:00.000Z");
  assert.equal(store.records[fingerprint].state, "accepted-risk");
  assert.equal(store.records[fingerprint].reviewAt, undefined);
});

test("review deadline validation fails closed on malformed timestamps", () => {
  const current = report();
  const fingerprint = current.findings[0].fingerprint;
  const store = reconcileLifecycle(current, emptyLifecycleStore());
  assert.throws(() => setFindingReviewAt(store, fingerprint, "not-a-date"), /valid timestamp/);
  assert.throws(() => setFindingState(store, fingerprint, "accepted-risk", { reviewAt: "not-a-date" }), /valid timestamp/);
  assert.equal(isLifecycleStore({
    schemaVersion: 1,
    records: {
      [fingerprint]: {
        fingerprint,
        state: "accepted-risk",
        updatedAt: "2026-08-22T20:00:00.000Z",
        reviewAt: "not-a-date",
      },
    },
  }), false);
});
