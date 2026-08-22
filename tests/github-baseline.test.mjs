import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadValidatedGitHubBaseline } from "../packages/github/dist/baseline.js";

function report(commitSha) {
  return {
    schemaVersion: "1.0",
    reportId: `baseline-${commitSha}`,
    generatedAt: "2026-08-22T15:45:00.000Z",
    toolVersion: "0.2.0",
    target: { path: "/workspace", commitSha },
    scanners: [{ scanner: "opengrep", startedAt: "a", completedAt: "b", findingCount: 0, artifactCount: 0, diagnostics: [] }],
    rawFindingCount: 0,
    findingCount: 0,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
    securityScore: 100,
    findings: [],
    scope: { mode: "repository" },
  };
}

async function withBaseline(commitSha, callback) {
  const root = await mkdtemp(join(tmpdir(), "synsec-github-baseline-"));
  const path = join(root, "baseline.json");
  await writeFile(path, JSON.stringify(report(commitSha)));
  try {
    await callback(path);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("local PR baseline must match the event payload base commit", async () => {
  await withBaseline("abcdef1234567890", async (path) => {
    const loaded = await loadValidatedGitHubBaseline(path, {
      repository: "cmahmud/synsec",
      sha: "9999999999999999",
      baseSha: "abcdef1234567890",
      baseRef: "main",
      pullRequestNumber: 2,
    });
    assert.equal(loaded.target.commitSha, "abcdef1234567890");
  });
});

test("baseline commit comparison accepts an unambiguous git SHA prefix", async () => {
  await withBaseline("abcdef1234567890abcdef1234567890abcdef12", async (path) => {
    const loaded = await loadValidatedGitHubBaseline(path, {
      repository: "cmahmud/synsec",
      sha: "9999999999999999",
      baseSha: "abcdef123456",
      pullRequestNumber: 2,
    });
    assert.equal(loaded.reportId.startsWith("baseline-abcdef"), true);
  });
});

test("stale local baselines fail before scanning", async () => {
  await withBaseline("1111111111111111", async (path) => {
    await assert.rejects(
      () => loadValidatedGitHubBaseline(path, {
        repository: "cmahmud/synsec",
        sha: "9999999999999999",
        baseSha: "2222222222222222",
        pullRequestNumber: 2,
      }),
      /baseline report commit does not match the expected base commit/,
    );
  });
});

test("PR baseline loading fails closed when no expected base commit is available", async () => {
  await withBaseline("abcdef1234567890", async (path) => {
    await assert.rejects(
      () => loadValidatedGitHubBaseline(path, {
        repository: "cmahmud/synsec",
        sha: "9999999999999999",
        pullRequestNumber: 2,
      }),
      /requires the pull-request base SHA or an explicit expected commit SHA/,
    );
  });
});

test("an explicit expected baseline commit supports non-PR/synthetic contexts", async () => {
  await withBaseline("abcdef1234567890", async (path) => {
    const loaded = await loadValidatedGitHubBaseline(path, {
      repository: "cmahmud/synsec",
      sha: "9999999999999999",
      ref: "refs/heads/main",
    }, { expectedCommitSha: "abcdef1234567890" });
    assert.equal(loaded.target.commitSha, "abcdef1234567890");
  });
});
