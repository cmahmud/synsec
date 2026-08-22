import assert from "node:assert/strict";
import test from "node:test";
import { buildReport } from "@synsec/report";
import { applyEvidenceAwareBaseline } from "@synsec/report/baseline";

function scan(scanner, findings) {
  return {
    scanner,
    startedAt: "2026-08-22T19:00:00.000Z",
    completedAt: "2026-08-22T19:00:01.000Z",
    target: { path: "/repo" },
    diagnostics: [],
    findings,
  };
}

function finding(id, scanner, path) {
  return {
    id,
    title: id,
    category: "sast",
    severity: "high",
    confidence: 1,
    scanner: { name: scanner, ruleId: id },
    ...(path ? { location: { path, startLine: 1 } } : {}),
  };
}

test("changed-file baseline does not mark findings outside the scanned path fixed", () => {
  const baseline = buildReport({
    target: { path: "/repo" },
    scans: [scan("fixture", [finding("old", "fixture", "src/untouched.ts")])],
    scope: { mode: "repository" },
  });
  const current = buildReport({
    target: { path: "/repo" },
    scans: [scan("fixture", [])],
    scope: { mode: "changed-files", baseRef: "base-sha", changedFiles: ["src/changed.ts"] },
  });
  const compared = applyEvidenceAwareBaseline(current, baseline);
  assert.deepEqual(compared.baseline.fixed, []);
});

test("changed-file baseline can mark an absent covered finding fixed when its scanner reran", () => {
  const baseline = buildReport({
    target: { path: "/repo" },
    scans: [scan("fixture", [finding("old", "fixture", "src/changed.ts")])],
  });
  const current = buildReport({
    target: { path: "/repo" },
    scans: [scan("fixture", [])],
    scope: { mode: "changed-files", changedFiles: ["SRC\\changed.ts"] },
  });
  const compared = applyEvidenceAwareBaseline(current, baseline);
  assert.equal(compared.baseline.fixed.length, 1);
});

test("baseline does not call an absent finding fixed when its detecting scanner did not rerun", () => {
  const baseline = buildReport({
    target: { path: "/repo" },
    scans: [scan("scanner-a", [finding("old", "scanner-a", "src/app.ts")])],
  });
  const current = buildReport({
    target: { path: "/repo" },
    scans: [scan("scanner-b", [])],
    scope: { mode: "repository" },
  });
  const compared = applyEvidenceAwareBaseline(current, baseline);
  assert.deepEqual(compared.baseline.fixed, []);
});

test("baseline still reports new and persisting findings deterministically", () => {
  const baselineFinding = finding("persist", "fixture", "src/app.ts");
  const baseline = buildReport({ target: { path: "/repo" }, scans: [scan("fixture", [baselineFinding])] });
  const current = buildReport({
    target: { path: "/repo" },
    scans: [scan("fixture", [baselineFinding, finding("new", "fixture", "src/new.ts")])],
    scope: { mode: "repository" },
  });
  const compared = applyEvidenceAwareBaseline(current, baseline);
  assert.equal(compared.baseline.new.length, 1);
  assert.equal(compared.baseline.persisting.length, 1);
  assert.deepEqual(compared.baseline.fixed, []);
});
