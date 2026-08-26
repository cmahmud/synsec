import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  appendHistoryReport,
  buildHistoryFromStore,
  readHistoryStore,
  snapshotReport,
} from "../packages/report/dist/history-store.js";

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
      description: "sensitive source context that must not be persisted in history",
      location: { path: "src/app.ts", startLine: 12, snippet: "const secret = process.env.TOKEN" },
    },
    duplicates: [],
    sources: [{ name: "test" }],
  };
}

function report(id, generatedAt, findings) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
  for (const item of findings) summary[item.primary.severity] += 1;
  return {
    schemaVersion: "1.0",
    reportId: id,
    generatedAt,
    toolVersion: "0.2.0",
    target: { path: ".", commitSha: id, branch: "main", repositoryUrl: "https://example.invalid/repo" },
    scanners: [],
    rawFindingCount: findings.length,
    findingCount: findings.length,
    summary,
    securityScore: 100 - findings.length * 10,
    findings,
  };
}

test("snapshotReport retains only trend-safe finding metadata", () => {
  const snapshot = snapshotReport(report("r1", "2026-08-20T12:00:00.000Z", [finding("a", "Finding A", "high")]));
  const serialized = JSON.stringify(snapshot);
  assert.equal(serialized.includes("sensitive source context"), false);
  assert.equal(serialized.includes("process.env.TOKEN"), false);
  assert.equal(serialized.includes("example.invalid"), false);
  assert.deepEqual(snapshot.findings[0], {
    fingerprint: "a",
    primary: { title: "Finding A", severity: "high" },
  });
});

test("history store is bounded, ordered, idempotent, and trend-compatible", async () => {
  const directory = await mkdtemp(join(tmpdir(), "synsec-history-"));
  const path = join(directory, "history.json");
  const r1 = report("r1", "2026-08-20T12:00:00.000Z", [finding("a", "A")]);
  const r2 = report("r2", "2026-08-21T12:00:00.000Z", [finding("a", "A"), finding("b", "B", "high")]);
  const r3 = report("r3", "2026-08-22T12:00:00.000Z", [finding("b", "B", "high")]);

  await appendHistoryReport(path, r2, { maxReports: 2 });
  await appendHistoryReport(path, r1, { maxReports: 2 });
  await appendHistoryReport(path, r3, { maxReports: 2 });
  await appendHistoryReport(path, r3, { maxReports: 2 });

  const store = await readHistoryStore(path);
  assert.deepEqual(store.reports.map((item) => item.reportId), ["r2", "r3"]);
  const history = await buildHistoryFromStore(path);
  assert.deepEqual(history.points.map((item) => item.reportId), ["r2", "r3"]);
  assert.equal(history.points[1].fixedCount, 1);
  assert.equal(history.points[1].persistingCount, 1);

  const mode = (await import("node:fs/promises")).stat(path).then((stat) => stat.mode & 0o777);
  assert.equal(await mode, 0o600);
});

test("history store rejects invalid retention and corrupt content", async () => {
  const directory = await mkdtemp(join(tmpdir(), "synsec-history-invalid-"));
  const path = join(directory, "history.json");
  const r1 = report("r1", "2026-08-20T12:00:00.000Z", []);
  await assert.rejects(() => appendHistoryReport(path, r1, { maxReports: 0 }), /between 1 and/);

  await (await import("node:fs/promises")).writeFile(path, "{broken", "utf8");
  await assert.rejects(() => readHistoryStore(path), /not valid JSON/);
  assert.equal((await readFile(path, "utf8")), "{broken");
});
