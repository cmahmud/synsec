import test from "node:test";
import assert from "node:assert/strict";

import { buildReportHistory } from "../packages/report/dist/history.js";

function finding(fingerprint, title, severity = "medium") {
  return {
    fingerprint,
    primary: {
      id: fingerprint,
      title,
      category: "sast",
      severity,
      confidence: 0.9,
      scanner: { name: "test" },
    },
    duplicates: [],
    sources: [{ name: "test" }],
  };
}

function report({ id, at, score, findings, sha = id }) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
  for (const item of findings) summary[item.primary.severity] += 1;
  return {
    schemaVersion: "1.0",
    reportId: id,
    generatedAt: at,
    toolVersion: "0.2.0",
    target: { path: ".", commitSha: sha, branch: "main" },
    scanners: [],
    rawFindingCount: findings.length,
    findingCount: findings.length,
    summary,
    securityScore: score,
    findings,
  };
}

test("buildReportHistory sorts reports and derives finding churn", () => {
  const first = report({
    id: "r1",
    at: "2026-08-20T12:00:00.000Z",
    score: 70,
    findings: [finding("a", "Finding A", "high"), finding("b", "Finding B", "medium")],
  });
  const second = report({
    id: "r2",
    at: "2026-08-21T12:00:00.000Z",
    score: 78,
    findings: [finding("a", "Finding A", "high"), finding("c", "Finding C", "low")],
  });
  const third = report({
    id: "r3",
    at: "2026-08-22T12:00:00.000Z",
    score: 90,
    findings: [finding("c", "Finding C escalated", "medium")],
  });

  const history = buildReportHistory([third, first, second]);
  assert.deepEqual(history.points.map((point) => point.reportId), ["r1", "r2", "r3"]);
  assert.deepEqual(
    history.points.map(({ newCount, fixedCount, persistingCount }) => ({ newCount, fixedCount, persistingCount })),
    [
      { newCount: 2, fixedCount: 0, persistingCount: 0 },
      { newCount: 1, fixedCount: 1, persistingCount: 1 },
      { newCount: 0, fixedCount: 1, persistingCount: 1 },
    ],
  );
  assert.equal(history.scoreDelta, 20);
  assert.equal(history.findingCountDelta, -1);

  const a = history.findings.find((item) => item.fingerprint === "a");
  const c = history.findings.find((item) => item.fingerprint === "c");
  assert.equal(a.occurrenceCount, 2);
  assert.equal(a.presentInLatest, false);
  assert.equal(c.occurrenceCount, 2);
  assert.equal(c.presentInLatest, true);
  assert.equal(c.highestSeverity, "medium");
  assert.equal(c.title, "Finding C escalated");
});

test("empty history is stable and machine-readable", () => {
  assert.deepEqual(buildReportHistory([]), {
    schemaVersion: 1,
    points: [],
    findings: [],
    scoreDelta: 0,
    findingCountDelta: 0,
  });
});

test("history rejects duplicate report ids and invalid timestamps", () => {
  const base = report({ id: "same", at: "2026-08-22T12:00:00.000Z", score: 100, findings: [] });
  assert.throws(() => buildReportHistory([base, { ...base, generatedAt: "2026-08-23T12:00:00.000Z" }]), /Duplicate report id/);
  assert.throws(() => buildReportHistory([{ ...base, reportId: "invalid-time", generatedAt: "not-a-date" }]), /invalid generatedAt/);
});
