import test from "node:test";
import assert from "node:assert/strict";
import { buildReport, applyBaseline, renderHtml, toSarif } from "../packages/report/dist/index.js";

function scan(ruleId, severity = "high") {
  return {
    scanner: "fixture",
    startedAt: "2026-01-01T00:00:00.000Z",
    completedAt: "2026-01-01T00:00:01.000Z",
    target: { path: "/repo" },
    diagnostics: [],
    findings: [{
      id: `id-${ruleId}`,
      title: `Finding ${ruleId}`,
      category: "sast",
      severity,
      confidence: 0.9,
      scanner: { name: "fixture", ruleId },
      location: { path: "src/app.ts", startLine: 10 },
    }],
  };
}

test("buildReport produces a versioned correlated report and security score", () => {
  const report = buildReport({ target: { path: "/repo" }, scans: [scan("RULE-1")] });
  assert.equal(report.schemaVersion, "1.0");
  assert.equal(report.rawFindingCount, 1);
  assert.equal(report.findingCount, 1);
  assert.equal(report.summary.high, 1);
  assert.ok(report.securityScore < 100);
});

test("baseline delta identifies new and fixed findings", () => {
  const previous = buildReport({ target: { path: "/repo" }, scans: [scan("OLD")] });
  const current = buildReport({ target: { path: "/repo" }, scans: [scan("NEW")] });
  const compared = applyBaseline(current, previous);
  assert.equal(compared.baseline.new.length, 1);
  assert.equal(compared.baseline.fixed.length, 1);
  assert.equal(compared.baseline.persisting.length, 0);
});

test("SARIF and HTML exports preserve findings without executable report content", () => {
  const report = buildReport({ target: { path: "/repo" }, scans: [scan("RULE-1")] });
  const sarif = toSarif(report);
  assert.equal(sarif.version, "2.1.0");
  const html = renderHtml(report);
  assert.match(html, /SynSec repository security/);
  assert.match(html, /Finding RULE-1/);
});
