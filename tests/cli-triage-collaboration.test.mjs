import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { buildReport } from "@synsec/report";

const exec = promisify(execFile);
const cli = new URL("../apps/cli/dist/index.js", import.meta.url);

function reportFor(root) {
  return buildReport({
    target: { path: root },
    scans: [{
      scanner: "fixture",
      startedAt: "2026-08-22T19:00:00.000Z",
      completedAt: "2026-08-22T19:00:01.000Z",
      target: { path: root },
      diagnostics: [],
      findings: [{
        id: "TRIAGE-1",
        title: "Needs human review",
        category: "sast",
        severity: "high",
        confidence: 1,
        scanner: { name: "fixture", ruleId: "TRIAGE-1" },
        location: { path: "src/app.ts", startLine: 2 },
      }],
    }],
    scope: { mode: "repository" },
  });
}

test("CLI triage can assign ownership and append bounded review comments", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-cli-collab-"));
  try {
    const report = reportFor(root);
    const fingerprint = report.findings[0].fingerprint;
    const reportPath = join(root, "report.json");
    const lifecyclePath = join(root, "lifecycle.json");
    const commentsPath = join(root, "review-comments.json");
    await writeFile(reportPath, JSON.stringify(report), "utf8");

    const owner = await exec(process.execPath, [
      cli.pathname, "triage", reportPath, fingerprint, "owner", "--note", "appsec", "--store", lifecyclePath,
    ]);
    assert.match(owner.stdout, /Assigned .* -> appsec/);
    const lifecycle = JSON.parse(await readFile(lifecyclePath, "utf8"));
    assert.equal(lifecycle.records[fingerprint].owner, "appsec");

    const comment = await exec(process.execPath, [
      cli.pathname, "triage", reportPath, fingerprint, "comment", "--note", "verify authorization boundary", "--store", lifecyclePath,
    ]);
    assert.match(comment.stdout, /Added review comment/);
    const comments = JSON.parse(await readFile(commentsPath, "utf8"));
    assert.equal(comments.comments[fingerprint].length, 1);
    assert.equal(comments.comments[fingerprint][0].body, "verify authorization boundary");

    const listed = await exec(process.execPath, [
      cli.pathname, "triage", reportPath, "--list", "--store", lifecyclePath,
    ]);
    assert.match(listed.stdout, /owner:appsec/);
    assert.match(listed.stdout, /comments:1/);
    assert.match(listed.stdout, /Review comments:/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("CLI triage refuses ownership/comments for fingerprints absent from the report", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-cli-collab-reject-"));
  try {
    const reportPath = join(root, "report.json");
    await writeFile(reportPath, JSON.stringify(reportFor(root)), "utf8");
    await assert.rejects(
      exec(process.execPath, [cli.pathname, "triage", reportPath, "not-a-real-fingerprint", "comment", "--note", "should fail"]),
      (error) => {
        assert.match(String(error.stderr), /fingerprint is not present/);
        return true;
      },
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
