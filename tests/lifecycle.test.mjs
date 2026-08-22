import test from "node:test";
import assert from "node:assert/strict";
import { buildReport } from "../packages/report/dist/index.js";
import {
  emptyLifecycleStore,
  lifecycleSummary,
  reconcileLifecycle,
  setFindingState,
} from "../packages/lifecycle/dist/index.js";

function reportWith(ruleIds) {
  return buildReport({
    target: { path: "/repo" },
    scans: [{
      scanner: "fixture",
      startedAt: "2026-01-01T00:00:00.000Z",
      completedAt: "2026-01-01T00:00:01.000Z",
      target: { path: "/repo" },
      diagnostics: [],
      findings: ruleIds.map((ruleId) => ({
        id: ruleId,
        title: `Finding ${ruleId}`,
        category: "sast",
        severity: "high",
        confidence: 1,
        scanner: { name: "fixture", ruleId },
        location: { path: `src/${ruleId}.ts`, startLine: 1 },
      })),
    }],
  });
}

test("lifecycle creates new findings and preserves explicit triage state", () => {
  const report = reportWith(["A"]);
  let store = reconcileLifecycle(report, emptyLifecycleStore(), "2026-01-01T00:00:00.000Z");
  const fingerprint = report.findings[0].fingerprint;
  assert.equal(store.records[fingerprint].state, "new");

  store = setFindingState(store, fingerprint, "confirmed", {
    note: "Reviewed by maintainer",
    reportId: report.reportId,
    updatedAt: "2026-01-02T00:00:00.000Z",
  });
  const next = reconcileLifecycle(report, store, "2026-01-03T00:00:00.000Z");
  assert.equal(next.records[fingerprint].state, "confirmed");
  assert.equal(next.records[fingerprint].note, "Reviewed by maintainer");
});

test("lifecycle marks disappeared confirmed findings fixed and returning findings regressed", () => {
  const initial = reportWith(["A"]);
  const fingerprint = initial.findings[0].fingerprint;
  let store = reconcileLifecycle(initial, emptyLifecycleStore(), "2026-01-01T00:00:00.000Z");
  store = setFindingState(store, fingerprint, "confirmed", { updatedAt: "2026-01-02T00:00:00.000Z" });

  const fixed = reconcileLifecycle(reportWith([]), store, "2026-01-03T00:00:00.000Z");
  assert.equal(fixed.records[fingerprint].state, "fixed");

  const regressed = reconcileLifecycle(initial, fixed, "2026-01-04T00:00:00.000Z");
  assert.equal(regressed.records[fingerprint].state, "regressed");
  assert.equal(lifecycleSummary(regressed).regressed, 1);
});

test("false-positive and accepted-risk decisions are not rewritten just because a later scan omits the finding", () => {
  const report = reportWith(["A", "B"]);
  const [a, b] = report.findings.map((finding) => finding.fingerprint);
  let store = reconcileLifecycle(report, emptyLifecycleStore());
  store = setFindingState(store, a, "false-positive");
  store = setFindingState(store, b, "accepted-risk");

  const next = reconcileLifecycle(reportWith([]), store);
  assert.equal(next.records[a].state, "false-positive");
  assert.equal(next.records[b].state, "accepted-risk");
});
