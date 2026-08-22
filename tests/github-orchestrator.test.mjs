import test from "node:test";
import assert from "node:assert/strict";

import { publishSynSecReportToGitHub } from "../packages/github/dist/orchestrator.js";

function report() {
  return {
    schemaVersion: "1.0",
    reportId: "report-orchestrator",
    generatedAt: "2026-08-22T14:00:00.000Z",
    toolVersion: "0.2.0",
    target: { path: ".", commitSha: "real-head-sha" },
    scanners: [{ scanner: "opengrep", startedAt: "a", completedAt: "b", findingCount: 1, artifactCount: 0, diagnostics: [] }],
    rawFindingCount: 1,
    findingCount: 1,
    summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0, unknown: 0 },
    securityScore: 90,
    findings: [{
      fingerprint: "fp-orchestrator",
      primary: {
        id: "finding-1",
        title: "Unsafe input",
        description: "Untrusted input reaches a sensitive operation.",
        category: "sast",
        severity: "high",
        confidence: 0.95,
        scanner: { name: "opengrep", ruleId: "unsafe-input" },
        location: { path: "src/app.ts", startLine: 8, endLine: 8 },
      },
      duplicates: [],
      sources: [{ name: "opengrep", ruleId: "unsafe-input" }],
    }],
    scope: { mode: "changed-files", baseRef: "main", changedFiles: ["src/app.ts"] },
    baseline: { new: ["fp-orchestrator"], fixed: [], persisting: [] },
  };
}

test("publishSynSecReportToGitHub resolves PR head context, builds, and publishes one completed check", async () => {
  let request;
  const fakeFetch = async (url, init) => {
    request = { url, init };
    return new Response(JSON.stringify({ id: 321, status: "completed", conclusion: "failure" }), { status: 201 });
  };

  const result = await publishSynSecReportToGitHub(report(), "installation-token", {
    env: {
      GITHUB_REPOSITORY: "cmahmud/synsec",
      GITHUB_SHA: "real-head-sha",
      GITHUB_REF: "refs/pull/2/head",
      GITHUB_BASE_REF: "main",
      GITHUB_HEAD_REF: "feature/multi-scanner-mvp",
    },
    fetch: fakeFetch,
    threshold: "high",
  });

  assert.equal(result.context.sha, "real-head-sha");
  assert.equal(result.context.pullRequestNumber, 2);
  assert.equal(result.check.headSha, "real-head-sha");
  assert.equal(result.check.conclusion, "failure");
  assert.equal(result.check.output.annotations.length, 1);
  assert.equal(request.url, "https://api.github.com/repos/cmahmud/synsec/check-runs");
  assert.equal(JSON.parse(request.init.body).head_sha, "real-head-sha");
  assert.equal(result.publication.id, 321);
});

test("publication orchestration fails before transport when GitHub context is missing", async () => {
  let called = false;
  await assert.rejects(
    () => publishSynSecReportToGitHub(report(), "token", {
      env: {},
      fetch: async () => {
        called = true;
        throw new Error("transport should not run");
      },
    }),
    /Unable to resolve a valid GitHub repository and commit context/,
  );
  assert.equal(called, false);
});

test("publication orchestration rejects a report generated for a different commit", async () => {
  let called = false;
  const stale = report();
  stale.target.commitSha = "old-head-sha";

  await assert.rejects(
    () => publishSynSecReportToGitHub(stale, "token", {
      env: { GITHUB_REPOSITORY: "cmahmud/synsec", GITHUB_SHA: "new-head-sha" },
      fetch: async () => {
        called = true;
        throw new Error("transport should not run");
      },
    }),
    /report commit does not match the GitHub commit/,
  );
  assert.equal(called, false);
});
