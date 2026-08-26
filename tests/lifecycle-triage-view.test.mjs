import assert from "node:assert/strict";
import test from "node:test";

import { buildReport } from "@synsec/report";
import {
  emptyLifecycleStore,
  reconcileLifecycle,
  setFindingOwner,
  setFindingState,
} from "@synsec/lifecycle";
import {
  addFindingReviewComment,
  emptyFindingReviewCommentStore,
} from "@synsec/lifecycle/review-comments";
import { buildFindingTriageView } from "@synsec/lifecycle/triage-view";

function report() {
  return buildReport({
    target: { path: "/repo" },
    scans: [{
      scanner: "fixture",
      startedAt: "2026-08-22T19:00:00.000Z",
      completedAt: "2026-08-22T19:00:01.000Z",
      target: { path: "/repo" },
      diagnostics: ["scanner detail that must not enter triage view"],
      findings: [{
        id: "A",
        title: "Finding A",
        description: "scanner evidence",
        category: "sast",
        severity: "high",
        confidence: 1,
        scanner: { name: "fixture", ruleId: "A" },
        location: { path: "src/a.ts", startLine: 10 },
        metadata: { sourceExcerpt: "sensitive source" },
      }, {
        id: "B",
        title: "Finding B",
        category: "dependency",
        severity: "medium",
        confidence: 1,
        scanner: { name: "fixture", ruleId: "B" },
      }],
    }],
    scope: { mode: "repository" },
  });
}

test("triage view composes current state ownership and comments without scanner/source evidence", () => {
  const current = report();
  const [a, b] = current.findings.map((finding) => finding.fingerprint);
  let lifecycle = reconcileLifecycle(current, emptyLifecycleStore(), "2026-08-22T19:01:00.000Z");
  lifecycle = setFindingState(lifecycle, a, "confirmed", {
    note: "Needs remediation",
    updatedAt: "2026-08-22T19:02:00.000Z",
  });
  lifecycle = setFindingOwner(lifecycle, a, "appsec", "2026-08-22T19:03:00.000Z");

  let comments = emptyFindingReviewCommentStore();
  comments = addFindingReviewComment(comments, a, "Reviewed with maintainers.", {
    author: "appsec",
    createdAt: "2026-08-22T19:04:00.000Z",
  });
  comments = addFindingReviewComment(comments, "not-current", "Historical only.", {
    createdAt: "2026-08-22T19:05:00.000Z",
  });

  const view = buildFindingTriageView(current, lifecycle, comments);
  assert.equal(view.interpretation, "triage-metadata-not-scanner-evidence");
  assert.deepEqual(view.summary, { current: 2, assigned: 1, unassigned: 1, commented: 1 });
  assert.equal(view.items.length, 2);

  const itemA = view.items.find((item) => item.fingerprint === a);
  const itemB = view.items.find((item) => item.fingerprint === b);
  assert.equal(itemA.state, "confirmed");
  assert.equal(itemA.owner, "appsec");
  assert.equal(itemA.note, "Needs remediation");
  assert.equal(itemA.comments[0].body, "Reviewed with maintainers.");
  assert.equal(itemB.state, "new");
  assert.equal(itemB.owner, undefined);

  const serialized = JSON.stringify(view);
  assert.equal(serialized.includes("src/a.ts"), false);
  assert.equal(serialized.includes("sensitive source"), false);
  assert.equal(serialized.includes("scanner detail"), false);
  assert.equal(serialized.includes("Historical only"), false);
});

test("triage view omits findings without lifecycle state rather than manufacturing review state", () => {
  const current = report();
  const view = buildFindingTriageView(current, emptyLifecycleStore(), emptyFindingReviewCommentStore());
  assert.deepEqual(view.items, []);
  assert.deepEqual(view.summary, { current: 0, assigned: 0, unassigned: 0, commented: 0 });
});
