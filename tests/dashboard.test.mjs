import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { renderProjectDashboardIndex, writeProjectDashboard } from "@synsec/dashboard";
import { buildReport } from "@synsec/report";
import { buildReportHistory } from "@synsec/report/history";

function input() {
  const report = buildReport({
    target: { path: "/repo" },
    scans: [{
      scanner: "fixture",
      startedAt: "2026-08-22T19:00:00.000Z",
      completedAt: "2026-08-22T19:00:01.000Z",
      target: { path: "/repo" },
      diagnostics: ["secret scanner diagnostic must stay out"],
      findings: [{
        id: "A",
        title: "Finding A",
        category: "sast",
        severity: "high",
        confidence: 1,
        scanner: { name: "fixture" },
        location: { path: "src/private.ts", startLine: 4 },
        evidence: "private source evidence",
      }],
      artifacts: [{
        type: "sbom",
        format: "syft-json",
        producer: "fixture",
        generatedAt: "2026-08-22T19:00:01.000Z",
        packageCount: 1,
        packages: [{ name: "dependency", version: "1.0.0", purl: "pkg:npm/dependency@1.0.0" }],
      }],
    }],
  });
  return {
    report,
    triage: {
      schemaVersion: 1,
      reportId: report.reportId,
      items: [{
        fingerprint: report.findings[0].fingerprint,
        title: "Finding A",
        severity: "high",
        state: "confirmed",
        updatedAt: "2026-08-22T19:01:00.000Z",
        owner: "appsec",
        comments: [],
      }],
      summary: { current: 1, assigned: 1, unassigned: 0, commented: 0 },
      interpretation: "triage-metadata-not-scanner-evidence",
    },
    posture: {
      schemaVersion: 1,
      indexedFileCount: 10,
      routeCount: 2,
      routeAuth: {
        "authorization-signal-observed": 1,
        "authentication-signal-observed": 0,
        "no-auth-signal-observed": 1,
      },
      routeSinkKinds: { process: 0, filesystem: 0, database: 1, network: 0 },
      routesWithSinkSignals: 1,
      routesWithoutAuthSignals: 1,
      interpretation: "bounded-lexical-posture-only",
    },
  };
}

function historyFor(current) {
  const previous = {
    reportId: "previous-report",
    generatedAt: "2026-08-21T19:00:00.000Z",
    target: { commitSha: "a".repeat(40), branch: "main" },
    securityScore: 82,
    findingCount: 2,
    summary: { critical: 0, high: 1, medium: 1, low: 0, info: 0, unknown: 0 },
    findings: [
      { fingerprint: "prior-a", primary: { title: "Prior A", severity: "high" } },
      { fingerprint: "prior-b", primary: { title: "Prior B", severity: "medium" } },
    ],
  };
  const latest = {
    reportId: current.reportId,
    generatedAt: "2026-08-22T19:00:00.000Z",
    target: { commitSha: "b".repeat(40), branch: "main" },
    securityScore: current.securityScore,
    findingCount: current.findingCount,
    summary: current.summary,
    findings: current.findings.map((finding) => ({
      fingerprint: finding.fingerprint,
      primary: { title: finding.primary.title, severity: finding.primary.severity },
    })),
  };
  return buildReportHistory([previous, latest]);
}

test("project dashboard index links only fixed local sanitized views", () => {
  const html = renderProjectDashboardIndex(input());
  assert.match(html, /href="triage\.html"/);
  assert.match(html, /href="dependencies\.html"/);
  assert.match(html, /href="posture\.html"/);
  assert.equal(html.includes("history.html"), false);
  assert.equal(html.includes("src/private.ts"), false);
  assert.equal(html.includes("private source evidence"), false);
  assert.equal(html.includes("secret scanner diagnostic"), false);
  assert.equal(html.includes("http://"), false);
  assert.equal(html.includes("https://"), false);
  assert.match(html, /security score/);
});

test("project dashboard writer creates a restrictive four-page local bundle", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-project-dashboard-"));
  const destination = join(root, "dashboard");
  try {
    const paths = await writeProjectDashboard(destination, input());
    assert.deepEqual(Object.keys(paths).sort(), ["dependencies", "directory", "index", "posture", "triage"]);
    for (const path of [paths.index, paths.triage, paths.dependencies, paths.posture]) {
      const html = await readFile(path, "utf8");
      assert.match(html, /SynSec/);
      assert.equal(html.includes("private source evidence"), false);
      assert.equal(html.includes("secret scanner diagnostic"), false);
      if (process.platform !== "win32") assert.equal((await stat(path)).mode & 0o777, 0o600);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("project dashboard optionally includes the existing trend-safe history view", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-project-dashboard-history-"));
  const destination = join(root, "dashboard");
  try {
    const dashboardInput = input();
    dashboardInput.history = historyFor(dashboardInput.report);
    const indexHtml = renderProjectDashboardIndex(dashboardInput);
    assert.match(indexHtml, /href="history\.html"/);
    assert.match(indexHtml, /<div class=value>2<\/div><div>historical scans<\/div>/);

    const paths = await writeProjectDashboard(destination, dashboardInput);
    assert.ok(paths.history);
    const historyHtml = await readFile(paths.history, "utf8");
    assert.match(historyHtml, /SynSec project security history/);
    assert.match(historyHtml, /Trend-safe repository security history/);
    assert.equal(historyHtml.includes("src/private.ts"), false);
    assert.equal(historyHtml.includes("private source evidence"), false);
    assert.equal(historyHtml.includes("secret scanner diagnostic"), false);
    if (process.platform !== "win32") assert.equal((await stat(paths.history)).mode & 0o777, 0o600);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
