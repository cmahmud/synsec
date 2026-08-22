import test from "node:test";
import assert from "node:assert/strict";
import { buildReport, applyBaseline, renderHtml, toSarif } from "../packages/report/dist/index.js";
import { renderMarkdown } from "../packages/report/dist/markdown.js";

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
      remediation: "Use a safer implementation.",
    }],
  };
}

test("buildReport produces a versioned correlated report and security score", () => {
  const report = buildReport({ target: { path: "/repo" }, scans: [scan("RULE-1")] });
  assert.equal(report.schemaVersion, "1.0");
  assert.equal(report.rawFindingCount, 1);
  assert.equal(report.findingCount, 1);
  assert.equal(report.summary.high, 1);
  assert.equal(report.scanners[0].artifactCount, 0);
  assert.ok(report.securityScore < 100);
});

test("buildReport preserves changed-file scan scope in JSON and HTML", () => {
  const report = buildReport({
    target: { path: "/repo" },
    scans: [scan("RULE-1")],
    scope: { mode: "changed-files", baseRef: "main", changedFiles: ["src/app.ts", "package.json"] },
  });
  assert.equal(report.scope.mode, "changed-files");
  assert.equal(report.scope.baseRef, "main");
  assert.deepEqual(report.scope.changedFiles, ["src/app.ts", "package.json"]);
  const html = renderHtml(report);
  assert.match(html, /2 changed file\(s\)/);
  assert.match(html, /since main/);
  const markdown = renderMarkdown(report);
  assert.match(markdown, /changed files since main \(2 files\)/);
});

test("buildReport preserves scanner artifacts and renders SBOM inventory", () => {
  const sbomScan = {
    scanner: "syft",
    startedAt: "2026-01-01T00:00:00.000Z",
    completedAt: "2026-01-01T00:00:01.000Z",
    target: { path: "/repo" },
    diagnostics: [],
    findings: [],
    artifacts: [{
      type: "sbom",
      format: "syft-json",
      producer: "syft",
      generatedAt: "2026-01-01T00:00:01.000Z",
      packageCount: 2,
      packages: [{ name: "a", version: "1.0.0" }, { name: "b", version: "2.0.0" }],
    }],
  };
  const report = buildReport({ target: { path: "/repo" }, scans: [sbomScan] });
  assert.equal(report.artifacts.length, 1);
  assert.equal(report.artifacts[0].packageCount, 2);
  assert.equal(report.scanners[0].artifactCount, 1);
  assert.match(renderHtml(report), /2 package\(s\) inventoried/);
  assert.match(renderMarkdown(report), /SBOM packages inventoried:\*\* 2/);
});

test("baseline delta identifies new and fixed findings", () => {
  const previous = buildReport({ target: { path: "/repo" }, scans: [scan("OLD")] });
  const current = buildReport({ target: { path: "/repo" }, scans: [scan("NEW")] });
  const compared = applyBaseline(current, previous);
  assert.equal(compared.baseline.new.length, 1);
  assert.equal(compared.baseline.fixed.length, 1);
  assert.equal(compared.baseline.persisting.length, 0);
});

test("SARIF, HTML, and Markdown exports preserve findings", () => {
  const report = buildReport({ target: { path: "/repo" }, scans: [scan("RULE-1")] });
  const sarif = toSarif(report);
  assert.equal(sarif.version, "2.1.0");
  const html = renderHtml(report);
  assert.match(html, /SynSec repository security/);
  assert.match(html, /Finding RULE-1/);
  const markdown = renderMarkdown(report);
  assert.match(markdown, /# SynSec Security Report/);
  assert.match(markdown, /\[HIGH\] Finding RULE-1/);
  assert.match(markdown, /Use a safer implementation/);
});
