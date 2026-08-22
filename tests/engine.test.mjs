import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defaultConfig } from "../packages/config/dist/index.js";
import {
  discoverChangedFiles,
  reportMeetsFailureThreshold,
  runScanEngine,
} from "../packages/engine/dist/index.js";
import { buildReport } from "../packages/report/dist/index.js";

const exec = promisify(execFile);

async function git(root, ...args) {
  return await exec("git", ["-C", root, ...args]);
}

test("scan engine refuses to produce a clean report when no selected scanner exists", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-engine-test-"));
  try {
    await writeFile(join(root, "README.md"), "fixture\n");
    const config = structuredClone(defaultConfig);
    config.scanners = ["scanner-that-does-not-exist"];
    await assert.rejects(
      runScanEngine({ rootPath: root, config }),
      /No selected scanner engines are available/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("changed-file discovery returns repository-relative files from the requested base", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-changed-test-"));
  try {
    await git(root, "init");
    await git(root, "config", "user.name", "SynSec Test");
    await git(root, "config", "user.email", "synsec-test@example.invalid");

    await writeFile(join(root, "a.txt"), "first\n");
    await git(root, "add", "a.txt");
    await git(root, "commit", "-m", "first");

    await writeFile(join(root, "b.txt"), "second\n");
    await git(root, "add", "b.txt");
    await git(root, "commit", "-m", "second");

    const scope = await discoverChangedFiles(root, "HEAD~1");
    assert.equal(scope.base, "HEAD~1");
    assert.deepEqual(scope.files, ["b.txt"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("failure threshold treats configured severity as inclusive", () => {
  const scan = {
    scanner: "fixture",
    startedAt: "2026-01-01T00:00:00.000Z",
    completedAt: "2026-01-01T00:00:01.000Z",
    target: { path: "/repo" },
    diagnostics: [],
    findings: [{
      id: "fixture",
      title: "Medium issue",
      category: "sast",
      severity: "medium",
      confidence: 0.9,
      scanner: { name: "fixture" },
    }],
  };
  const report = buildReport({ target: { path: "/repo" }, scans: [scan] });
  assert.equal(reportMeetsFailureThreshold(report, "high"), false);
  assert.equal(reportMeetsFailureThreshold(report, "medium"), true);
  assert.equal(reportMeetsFailureThreshold(report, "low"), true);
  assert.equal(reportMeetsFailureThreshold(report, "none"), false);
});
