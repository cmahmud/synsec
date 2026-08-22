import test from "node:test";
import assert from "node:assert/strict";

import { renderStepSummary } from "../apps/github-action/dist/summary.js";

function report() {
  return {
    schemaVersion: "1.0",
    reportId: "summary-report",
    generatedAt: "2026-08-22T15:20:00.000Z",
    toolVersion: "0.2.0",
    target: { path: "/workspace", commitSha: "abcdef1234567890" },
    scanners: [],
    rawFindingCount: 3,
    findingCount: 3,
    summary: { critical: 1, high: 1, medium: 1, low: 0, info: 0, unknown: 0 },
    securityScore: 58,
    findings: [],
    scope: { mode: "changed-files", baseRef: "origin/main", changedFiles: ["src/app.ts"] },
    baseline: { new: ["a", "b"], fixed: ["c"], persisting: ["d", "e", "f"] },
  };
}

test("job summary contains aggregate scan and baseline metadata only", () => {
  const value = report();
  value.findings = [{ primary: { title: "<script>scanner-controlled</script>" } }];
  const summary = renderStepSummary(value, "base-scan");

  assert.match(summary, /Security score:\*\* 58\/100/);
  assert.match(summary, /Findings:\*\* 3/);
  assert.match(summary, /Critical \| 1/);
  assert.match(summary, /New: \*\*2\*\*/);
  assert.match(summary, /Fixed: \*\*1\*\*/);
  assert.match(summary, /Persisting: \*\*3\*\*/);
  assert.match(summary, /Baseline:\*\* base-scan/);
  assert.doesNotMatch(summary, /scanner-controlled/);
  assert.doesNotMatch(summary, /src\/app\.ts/);
});
