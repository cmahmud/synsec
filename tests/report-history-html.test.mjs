import test from "node:test";
import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { renderHistoryHtml, writeHistoryHtml, writeHistoryHtmlFromStore } from "../packages/report/dist/history-html.js";

function history() {
  return {
    schemaVersion: 1,
    scoreDelta: 8,
    findingCountDelta: -1,
    points: [
      {
        reportId: "old",
        generatedAt: "2026-08-20T12:00:00.000Z",
        commitSha: "abcdef1234567890",
        securityScore: 82,
        findingCount: 2,
        summary: { critical: 0, high: 1, medium: 1, low: 0, info: 0, unknown: 0 },
        newCount: 2,
        fixedCount: 0,
        persistingCount: 0,
      },
      {
        reportId: "new",
        generatedAt: "2026-08-22T12:00:00.000Z",
        commitSha: "1234567890abcdef",
        securityScore: 90,
        findingCount: 1,
        summary: { critical: 0, high: 0, medium: 1, low: 0, info: 0, unknown: 0 },
        newCount: 0,
        fixedCount: 1,
        persistingCount: 1,
      },
    ],
    findings: [
      {
        fingerprint: "fp-1",
        title: "Unsafe <script>alert(1)</script>",
        highestSeverity: "medium",
        firstSeenAt: "2026-08-20T12:00:00.000Z",
        lastSeenAt: "2026-08-22T12:00:00.000Z",
        occurrenceCount: 2,
        presentInLatest: true,
      },
      {
        fingerprint: "fp-fixed",
        title: "Fixed finding",
        highestSeverity: "high",
        firstSeenAt: "2026-08-20T12:00:00.000Z",
        lastSeenAt: "2026-08-20T12:00:00.000Z",
        occurrenceCount: 1,
        presentInLatest: false,
      },
    ],
  };
}

test("renderHistoryHtml creates a self-contained trend dashboard", () => {
  const html = renderHistoryHtml(history(), { title: "Repository security" });
  assert.match(html, /<!doctype html>/);
  assert.match(html, /Repository security/);
  assert.match(html, /90\/100/);
  assert.match(html, /\+8/);
  assert.match(html, /-1/);
  assert.match(html, /Security score trend/);
  assert.match(html, /1234567890ab/);
  assert.equal(html.includes("Fixed finding"), false);
});

test("renderHistoryHtml escapes finding and title content", () => {
  const html = renderHistoryHtml(history(), { title: '<img src=x onerror="x">' });
  assert.equal(html.includes("<script>alert(1)</script>"), false);
  assert.match(html, /Unsafe &lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.equal(html.includes('<img src=x onerror="x">'), false);
  assert.match(html, /&lt;img src=x onerror=&quot;x&quot;&gt;/);
});

test("renderHistoryHtml handles empty history without malformed metrics", () => {
  const html = renderHistoryHtml({ schemaVersion: 1, points: [], findings: [], scoreDelta: 0, findingCountDelta: 0 });
  assert.match(html, /No scan history is available yet/);
  assert.match(html, /Active findings<\/span><strong>0/);
  assert.equal(html.includes("NaN"), false);
});

test("writeHistoryHtmlFromStore renders a trend-safe store to a restrictive local file", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-history-html-"));
  try {
    const storePath = join(root, "history.json");
    const outputPath = join(root, "dashboard", "index.html");
    await writeFile(storePath, JSON.stringify({
      schemaVersion: 1,
      reports: [{
        reportId: "stored",
        generatedAt: "2026-08-22T12:00:00.000Z",
        target: { commitSha: "abcdef1234567890", branch: "main" },
        securityScore: 94,
        findingCount: 1,
        summary: { critical: 0, high: 0, medium: 1, low: 0, info: 0, unknown: 0 },
        findings: [{ fingerprint: "fp", primary: { title: "Stored finding", severity: "medium" } }],
      }],
    }));

    const built = await writeHistoryHtmlFromStore(storePath, outputPath, { title: "Stored history" });
    const html = await readFile(outputPath, "utf8");
    const info = await stat(outputPath);
    assert.equal(built.points.length, 1);
    assert.match(html, /Stored history/);
    assert.match(html, /94\/100/);
    if (process.platform !== "win32") assert.equal(info.mode & 0o777, 0o600);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("history dashboard writer repairs permissive existing file modes where supported", async () => {
  if (process.platform === "win32") return;
  const root = await mkdtemp(join(tmpdir(), "synsec-history-html-mode-"));
  const outputPath = join(root, "history.html");
  try {
    await writeFile(outputPath, "old\n", { encoding: "utf8", mode: 0o644 });
    await chmod(outputPath, 0o644);
    await writeHistoryHtml(outputPath, history());
    assert.equal((await stat(outputPath)).mode & 0o777, 0o600);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
