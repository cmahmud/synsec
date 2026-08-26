import assert from "node:assert/strict";
import test from "node:test";

import { emptyLifecycleStore, reconcileLifecycle, setFindingReviewAt, setFindingState } from "@synsec/lifecycle";
import { emptyFindingReviewCommentStore } from "@synsec/lifecycle/review-comments";
import { renderFindingTriageHtml } from "@synsec/lifecycle/triage-html";
import { buildFindingTriageView } from "@synsec/lifecycle/triage-view";
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
        id: "REVIEW-DUE-1",
        title: "Accepted risk with review governance",
        category: "sast",
        severity: "medium",
        confidence: 1,
        scanner: { name: "fixture", ruleId: "REVIEW-DUE-1" },
        location: { path: "src/app.ts", startLine: 12 },
      }],
    }],
    scope: { mode: "repository" },
  });
}

test("triage derives due versus scheduled review status without changing lifecycle state", () => {
  const current = report();
  const fingerprint = current.findings[0].fingerprint;
  let store = reconcileLifecycle(current, emptyLifecycleStore(), "2026-08-22T20:01:00.000Z");
  store = setFindingState(store, fingerprint, "accepted-risk", { updatedAt: "2026-08-22T20:02:00.000Z" });
  store = setFindingReviewAt(store, fingerprint, "2026-09-01T00:00:00.000Z", "2026-08-22T20:03:00.000Z");

  const scheduled = buildFindingTriageView(current, store, emptyFindingReviewCommentStore(), {
    now: Date.parse("2026-08-31T23:59:59.000Z"),
  });
  assert.equal(scheduled.items[0].state, "accepted-risk");
  assert.equal(scheduled.items[0].reviewStatus, "scheduled");
  assert.match(renderFindingTriageHtml(scheduled), /Review by/);

  const due = buildFindingTriageView(current, store, emptyFindingReviewCommentStore(), {
    now: Date.parse("2026-09-01T00:00:00.000Z"),
  });
  assert.equal(due.items[0].state, "accepted-risk");
  assert.equal(due.items[0].reviewStatus, "due");
  assert.match(renderFindingTriageHtml(due), /Review overdue/);
  assert.equal(due.interpretation, "triage-metadata-not-scanner-evidence");
});
