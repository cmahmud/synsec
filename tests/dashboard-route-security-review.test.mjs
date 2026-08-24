import assert from "node:assert/strict";
import test from "node:test";

import { renderProjectDashboardIndex } from "@synsec/dashboard";
import { buildReport } from "@synsec/report";

function inputWithRouteReviews() {
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
  const base = {
    method: "POST",
    route: "/secret-bearing-route-ghp_abcdefghijklmnopqrstuvwxyz1234567890",
    handler: "credentialBearingHandler",
    sinkKinds: ["process"],
    protectionStatus: "not-assessed",
    callScope: "same-file",
    interpretation: "structural-route-security-review-context-only",
  };
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
    routeSecurityReviews: [
      { ...base, signal: "sensitive-sink-auth-context-unavailable" },
      { ...base, signal: "sensitive-sink-without-auth-signal", protectionStatus: "no-auth-signal-observed" },
      { ...base, signal: "sensitive-sink-with-authorization-signal", protectionStatus: "authorization-signal-observed" },
      { ...base, signal: "sensitive-sink-with-authentication-signal", protectionStatus: "authentication-signal-observed" },
    ],
  };
}

test("dashboard renders only validated aggregate route-security review counts", () => {
  const html = renderProjectDashboardIndex(inputWithRouteReviews());
  assert.match(html, /2<\/div><div>sensitive-sink auth reviews/);
  assert.match(html, /1 authorization signal · 1 authentication signal/);
  assert.match(html, /validated structural review context, not protection or exploitability verdicts/);
  assert.doesNotMatch(html, /credentialBearingHandler/);
  assert.doesNotMatch(html, /secret-bearing-route/);
  assert.doesNotMatch(html, /ghp_abcdefghijklmnopqrstuvwxyz1234567890/);
});

test("dashboard rejects inconsistent route-security metadata before rendering", () => {
  const input = inputWithRouteReviews();
  input.routeSecurityReviews[0].signal = "sensitive-sink-with-authorization-signal";
  assert.throws(
    () => renderProjectDashboardIndex(input),
    /inconsistent protection metadata/,
  );
});
