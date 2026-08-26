import assert from "node:assert/strict";
import test from "node:test";

import { renderProjectDashboardIndex } from "@synsec/dashboard";
import { buildReport } from "@synsec/report";

function dashboardInput() {
  const report = buildReport({
    target: { path: "/repo" },
    scans: [{
      scanner: "fixture",
      startedAt: "2026-08-23T00:00:00.000Z",
      completedAt: "2026-08-23T00:00:01.000Z",
      target: { path: "/repo" },
      diagnostics: [],
      findings: [],
    }],
  });
  return {
    report,
    triage: {
      schemaVersion: 1,
      reportId: report.reportId,
      items: [],
      summary: { current: 0, assigned: 0, unassigned: 0, commented: 0 },
      interpretation: "triage-metadata-not-scanner-evidence",
    },
    posture: {
      schemaVersion: 1,
      indexedFileCount: 0,
      routeCount: 0,
      routeAuth: {
        "authorization-signal-observed": 0,
        "authentication-signal-observed": 0,
        "no-auth-signal-observed": 0,
      },
      routeSinkKinds: { process: 0, filesystem: 0, database: 0, network: 0 },
      routesWithSinkSignals: 0,
      routesWithoutAuthSignals: 0,
      interpretation: "bounded-lexical-posture-only",
    },
    reviewDeadlines: {
      schemaVersion: 1,
      generatedAt: "2026-08-23T00:00:00.000Z",
      dueSoonWindowMs: 604800000,
      items: [{
        fingerprint: "review-fingerprint",
        state: "accepted-risk",
        reviewAt: "2026-08-22T00:00:00.000Z",
        status: "overdue",
      }],
      summary: { reviewable: 4, unscheduled: 2, overdue: 1, dueSoon: 1, scheduled: 0 },
    },
  };
}

test("dashboard shows aggregate lifecycle review health without item details", () => {
  const html = renderProjectDashboardIndex(dashboardInput());
  assert.match(html, /1<\/div><div>overdue exception reviews/);
  assert.match(html, /1 due soon · 2 unscheduled/);
  assert.match(html, /governance metadata, not scanner evidence/);
  assert.doesNotMatch(html, /review-fingerprint/);
  assert.doesNotMatch(html, /2026-08-22T00:00:00\.000Z/);
  assert.doesNotMatch(html, /accepted-risk/);
});
