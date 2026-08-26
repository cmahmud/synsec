import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { scanGitHubBaseCommit } from "../packages/github/dist/base-scan.js";

const exec = promisify(execFile);
const config = {
  version: 1,
  scanners: ["opengrep"],
  failOn: "high",
  parallelism: 1,
  timeoutMs: 60_000,
};

async function git(root, ...args) {
  return exec("git", ["-C", root, ...args], { encoding: "utf8" });
}

function outcome(rootPath, commitSha) {
  return {
    report: {
      schemaVersion: "1.0",
      reportId: "base-report",
      generatedAt: "2026-08-22T15:00:00.000Z",
      toolVersion: "0.2.0",
      target: { path: rootPath, commitSha },
      scanners: [],
      rawFindingCount: 0,
      findingCount: 0,
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
      securityScore: 100,
      findings: [],
      scope: { mode: "repository" },
    },
    repositoryIndex: { schemaVersion: "1.0", root: rootPath, files: [] },
    statuses: [],
    failures: [],
    shouldFail: false,
    changedFiles: [],
  };
}

test("base scan uses a detached local worktree and binds the report to the requested commit", async () => {
  const repository = await mkdtemp(join(tmpdir(), "synsec-base-test-"));
  let scannedRoot;
  try {
    await git(repository, "init");
    await git(repository, "config", "user.email", "synsec@example.invalid");
    await git(repository, "config", "user.name", "SynSec Test");
    await writeFile(join(repository, "app.js"), "export const secure = true;\n", "utf8");
    await git(repository, "add", "app.js");
    await git(repository, "commit", "-m", "base");
    const { stdout } = await git(repository, "rev-parse", "HEAD");
    const baseSha = stdout.trim();

    const result = await scanGitHubBaseCommit(config, repository, baseSha, {
      scan: async (input) => {
        scannedRoot = input.rootPath;
        assert.notEqual(scannedRoot, repository);
        assert.equal(input.changedOnly, false);
        assert.equal(await readFile(join(scannedRoot, "app.js"), "utf8"), "export const secure = true;\n");
        return outcome(scannedRoot, baseSha);
      },
    });

    assert.equal(result.report.target.commitSha, baseSha);
    await assert.rejects(() => access(scannedRoot));
    assert.equal((await git(repository, "status", "--porcelain")).stdout, "");
  } finally {
    await rm(repository, { recursive: true, force: true });
  }
});

test("base scan rejects non-SHA revisions before invoking git", async () => {
  await assert.rejects(
    () => scanGitHubBaseCommit(config, process.cwd(), "origin/main"),
    /valid commit SHA/,
  );
});
