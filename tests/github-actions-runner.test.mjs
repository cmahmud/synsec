import test from "node:test";
import assert from "node:assert/strict";

import { runGitHubActionsRepositoryScan } from "../packages/github/dist/actions-runner.js";

function report(commitSha = "abcdef1234567890") {
  return {
    schemaVersion: "1.0",
    reportId: "report-actions",
    generatedAt: "2026-08-22T14:30:00.000Z",
    toolVersion: "0.2.0",
    target: { path: "/workspace", commitSha },
    scanners: [{ scanner: "opengrep", startedAt: "a", completedAt: "b", findingCount: 0, artifactCount: 0, diagnostics: [] }],
    rawFindingCount: 0,
    findingCount: 0,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
    securityScore: 100,
    findings: [],
    scope: { mode: "changed-files", baseRef: "origin/main", changedFiles: ["src/app.ts"] },
  };
}

function outcome(commitSha = "abcdef1234567890") {
  return {
    report: report(commitSha),
    repositoryIndex: { schemaVersion: "1.0", root: "/workspace", files: [] },
    statuses: [],
    failures: [],
    shouldFail: false,
    changedFiles: ["src/app.ts"],
    changedBase: "origin/main",
  };
}

const config = {
  version: 1,
  scanners: ["opengrep"],
  failOn: "high",
  parallelism: 2,
  timeoutMs: 60_000,
};

test("PR Actions runner defaults to changed-file scanning and publishes the scanned head", async () => {
  let scanInput;
  let request;
  const result = await runGitHubActionsRepositoryScan("installation-token", {
    config,
    rootPath: "/workspace",
    env: {
      GITHUB_REPOSITORY: "cmahmud/synsec",
      GITHUB_SHA: "abcdef1234567890",
      GITHUB_REF: "refs/pull/2/head",
      GITHUB_BASE_REF: "main",
      GITHUB_HEAD_REF: "feature/multi-scanner-mvp",
    },
    scan: async (input) => {
      scanInput = input;
      return outcome();
    },
    fetch: async (url, init) => {
      request = { url, init };
      return new Response(JSON.stringify({ id: 444, status: "completed", conclusion: "success" }), { status: 201 });
    },
  });

  assert.equal(scanInput.rootPath, "/workspace");
  assert.equal(scanInput.changedOnly, true);
  assert.equal(scanInput.changedBase, "origin/main");
  assert.equal(result.context.pullRequestNumber, 2);
  assert.equal(result.publication.check.headSha, "abcdef1234567890");
  assert.equal(result.publication.publication.id, 444);
  assert.equal(request.url, "https://api.github.com/repos/cmahmud/synsec/check-runs");
  assert.equal(result.sarifPublication, undefined);
});

test("push Actions runner defaults to a full repository scan", async () => {
  let scanInput;
  await runGitHubActionsRepositoryScan("token", {
    config,
    env: {
      GITHUB_REPOSITORY: "cmahmud/synsec",
      GITHUB_SHA: "abcdef1234567890",
      GITHUB_REF: "refs/heads/main",
    },
    scan: async (input) => {
      scanInput = input;
      const value = outcome();
      value.report.scope = { mode: "repository" };
      return value;
    },
    fetch: async () => new Response(JSON.stringify({ id: 445, status: "completed", conclusion: "success" }), { status: 201 }),
  });

  assert.equal(scanInput.changedOnly, false);
  assert.equal(scanInput.changedBase, undefined);
});

test("Actions runner can publish the same commit-bound report to checks and code scanning", async () => {
  const urls = [];
  const result = await runGitHubActionsRepositoryScan("token", {
    config,
    publishSarif: true,
    env: {
      GITHUB_REPOSITORY: "cmahmud/synsec",
      GITHUB_SHA: "abcdef1234567890",
      GITHUB_REF: "refs/pull/2/head",
      GITHUB_BASE_REF: "main",
      GITHUB_HEAD_REF: "feature/multi-scanner-mvp",
    },
    scan: async () => outcome(),
    fetch: async (url) => {
      urls.push(url);
      if (url.endsWith("/check-runs")) {
        return new Response(JSON.stringify({ id: 446, status: "completed", conclusion: "success" }), { status: 201 });
      }
      if (url.endsWith("/code-scanning/sarifs")) {
        return new Response(JSON.stringify({ id: "sarif-446" }), { status: 202 });
      }
      throw new Error(`unexpected URL ${url}`);
    },
  });

  assert.deepEqual(urls, [
    "https://api.github.com/repos/cmahmud/synsec/check-runs",
    "https://api.github.com/repos/cmahmud/synsec/code-scanning/sarifs",
  ]);
  assert.equal(result.sarifPublication.id, "sarif-446");
  assert.equal(result.sarifPublication.ref, "refs/pull/2/head");
});

test("Actions runner refuses publication when the scan cannot prove its commit", async () => {
  let published = false;
  const value = outcome();
  delete value.report.target.commitSha;

  await assert.rejects(
    () => runGitHubActionsRepositoryScan("token", {
      config,
      env: { GITHUB_REPOSITORY: "cmahmud/synsec", GITHUB_SHA: "abcdef1234567890" },
      scan: async () => value,
      fetch: async () => {
        published = true;
        throw new Error("should not publish");
      },
    }),
    /must produce a report with a commit SHA/,
  );
  assert.equal(published, false);
});
