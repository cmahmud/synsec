import test from "node:test";
import assert from "node:assert/strict";

import { renderHistoryHtml } from "../packages/report/dist/history-html.js";

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
