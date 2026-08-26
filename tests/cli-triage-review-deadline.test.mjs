import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { execFile } from "node:child_process";
import test from "node:test";

import { readLifecycleStore } from "@synsec/lifecycle";
import { buildReport, writeReport } from "@synsec/report";

const execFileAsync = promisify(execFile);

function report() {
  return buildReport({
    target: { path: "/repo" },
    scans: [{
      scanner: "fixture",
      startedAt: "2026-08-22T20:00:00.000Z",
      completedAt: "2026-08-22T20:00:01.000Z",
      target: { path: "/repo" },
      diagnostics: [],
      findings: [{
        id: "REVIEW-CLI-1",
        title: "Review this accepted risk periodically",
        category: "sast",
        severity: "medium",
        confidence: 1,
        scanner: { name: "fixture", ruleId: "REVIEW-CLI-1" },
        location: { path: "src/app.ts", startLine: 9 },
      }],
    }],
    scope: { mode: "repository" },
  });
}

async function runCli(args) {
  return execFileAsync(process.execPath, ["apps/cli/dist/index.js", ...args], {
    cwd: process.cwd(),
    env: { ...process.env, NO_COLOR: "1" },
  });
}

test("CLI can set, list, and clear a human review deadline without changing accepted-risk state", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-cli-review-deadline-"));
  const reportPath = join(root, "report.json");
  const lifecyclePath = join(root, "lifecycle.json");
  try {
    const current = report();
    const fingerprint = current.findings[0].fingerprint;
    await writeReport(reportPath, current);

    await runCli(["triage", reportPath, fingerprint, "accepted-risk", "--store", lifecyclePath, "--note", "temporary vendor constraint"]);
    await runCli(["triage", reportPath, fingerprint, "review-at", "--store", lifecyclePath, "--note", "2026-11-01T12:00:00.000Z"]);

    let store = await readLifecycleStore(lifecyclePath);
    assert.equal(store.records[fingerprint].state, "accepted-risk");
    assert.equal(store.records[fingerprint].reviewAt, "2026-11-01T12:00:00.000Z");
    assert.equal(store.records[fingerprint].note, "temporary vendor constraint");

    const listed = await runCli(["triage", reportPath, "--list", "--store", lifecyclePath]);
    assert.match(listed.stdout, /accepted-risk/);
    assert.match(listed.stdout, /review:2026-11-01T12:00:00.000Z/);

    await runCli(["triage", reportPath, fingerprint, "review-at", "--store", lifecyclePath, "--note", "clear"]);
    store = await readLifecycleStore(lifecyclePath);
    assert.equal(store.records[fingerprint].state, "accepted-risk");
    assert.equal(store.records[fingerprint].reviewAt, undefined);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
