import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { renderProjectDashboardIndex, writeProjectDashboard } from "@synsec/dashboard";
import { buildReport } from "@synsec/report";

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

test("project dashboard index links only fixed local sanitized views", () => {
  const html = renderProjectDashboardIndex(input());
  assert.match(html, /href="triage\.html"/);
  assert.match(html, /href="dependencies\.html"/);
  assert.match(html, /href="posture\.html"/);
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
