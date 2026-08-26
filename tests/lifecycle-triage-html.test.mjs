import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { renderFindingTriageHtml, writeFindingTriageHtml } from "@synsec/lifecycle/triage-html";

function view() {
  return {
    schemaVersion: 1,
    reportId: "report-<unsafe>",
    items: [{
      fingerprint: "fp<&>",
      title: "Unsafe <script>alert(1)</script>",
      severity: "high",
      state: "confirmed",
      updatedAt: "2026-08-22T19:10:00.000Z",
      owner: "appsec <team>",
      note: "Needs <review> & follow-up",
      comments: [{
        id: "comment-1",
        fingerprint: "fp<&>",
        body: "Do not render <img src=x onerror=alert(1)>",
        author: "reviewer & owner",
        createdAt: "2026-08-22T19:11:00.000Z",
      }],
    }],
    summary: { current: 1, assigned: 1, unassigned: 0, commented: 1 },
    interpretation: "triage-metadata-not-scanner-evidence",
  };
}

test("triage HTML escapes every scanner/human-controlled display field", () => {
  const html = renderFindingTriageHtml(view());
  assert.match(html, /Unsafe &lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html, /report-&lt;unsafe&gt;/);
  assert.match(html, /appsec &lt;team&gt;/);
  assert.match(html, /Needs &lt;review&gt; &amp; follow-up/);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.match(html, /reviewer &amp; owner/);
  assert.equal(html.includes("<script>alert(1)</script>"), false);
  assert.equal(html.includes("<img src=x onerror=alert(1)>"), false);
  assert.match(html, /<meta name="robots" content="noindex,nofollow">/);
});

test("triage HTML writer uses restrictive permissions where supported", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-triage-html-"));
  const path = join(root, "triage", "index.html");
  try {
    await writeFindingTriageHtml(path, view());
    const html = await readFile(path, "utf8");
    assert.match(html, /SynSec finding triage/);
    if (process.platform !== "win32") assert.equal((await stat(path)).mode & 0o777, 0o600);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("empty triage view renders an explicit no-current-findings state", () => {
  const html = renderFindingTriageHtml({
    schemaVersion: 1,
    reportId: "empty",
    items: [],
    summary: { current: 0, assigned: 0, unassigned: 0, commented: 0 },
    interpretation: "triage-metadata-not-scanner-evidence",
  });
  assert.match(html, /No current lifecycle findings/);
});
