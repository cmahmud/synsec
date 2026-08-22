import test from "node:test";
import assert from "node:assert/strict";
import { gunzipSync } from "node:zlib";

import { publishGitHubSarif, sarifRefForContext } from "../packages/github/dist/sarif-publisher.js";

function report(commitSha = "abcdef1234567890") {
  return {
    schemaVersion: "1.0",
    reportId: "report-sarif",
    generatedAt: "2026-08-22T15:30:00.000Z",
    toolVersion: "0.2.0",
    target: { path: "/workspace", commitSha },
    scanners: [{ scanner: "opengrep", startedAt: "a", completedAt: "b", findingCount: 1, artifactCount: 0, diagnostics: [] }],
    rawFindingCount: 1,
    findingCount: 1,
    summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0, unknown: 0 },
    securityScore: 90,
    findings: [{
      fingerprint: "fp-sarif",
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
    scope: { mode: "repository" },
  };
}

test("SARIF ref uses the PR head ref that corresponds to the published head SHA", () => {
  assert.equal(sarifRefForContext({
    repository: "cmahmud/synsec",
    sha: "abcdef1234567890",
    ref: "refs/pull/2/merge",
    headRef: "feature/multi-scanner-mvp",
    pullRequestNumber: 2,
  }), "refs/pull/2/head");
  assert.equal(sarifRefForContext({
    repository: "cmahmud/synsec",
    sha: "abcdef1234567890",
    ref: "refs/heads/main",
  }), "refs/heads/main");
});

test("publishGitHubSarif uploads gzip/base64 SARIF only to GitHub code scanning", async () => {
  let request;
  const context = {
    repository: "cmahmud/synsec",
    sha: "abcdef1234567890",
    ref: "refs/pull/2/merge",
    pullRequestNumber: 2,
  };
  const result = await publishGitHubSarif(report(), context, "installation-token", {
    fetch: async (url, init) => {
      request = { url, init };
      return new Response(JSON.stringify({ id: "sarif-upload-1", url: "https://api.github.com/uploads/1" }), { status: 202 });
    },
  });

  assert.equal(request.url, "https://api.github.com/repos/cmahmud/synsec/code-scanning/sarifs");
  assert.equal(request.init.redirect, "error");
  assert.equal(request.init.headers.authorization, "Bearer installation-token");
  const body = JSON.parse(request.init.body);
  assert.equal(body.commit_sha, "abcdef1234567890");
  assert.equal(body.ref, "refs/pull/2/head");
  const decoded = JSON.parse(gunzipSync(Buffer.from(body.sarif, "base64")).toString("utf8"));
  assert.equal(decoded.version, "2.1.0");
  assert.equal(decoded.runs[0].results.length, 1);
  assert.equal(result.id, "sarif-upload-1");
  assert.equal(result.ref, "refs/pull/2/head");
  assert.equal(result.compressedBytes > 0, true);
});

test("SARIF publication rejects stale reports before transport", async () => {
  let called = false;
  await assert.rejects(
    () => publishGitHubSarif(report("1111111111111111"), {
      repository: "cmahmud/synsec",
      sha: "2222222222222222",
      ref: "refs/heads/main",
    }, "token", {
      fetch: async () => {
        called = true;
        throw new Error("transport should not run");
      },
    }),
    /report commit does not match.*SARIF publication/,
  );
  assert.equal(called, false);
});

test("SARIF publication redacts a token if GitHub error text reflects it", async () => {
  await assert.rejects(
    () => publishGitHubSarif(report(), {
      repository: "cmahmud/synsec",
      sha: "abcdef1234567890",
      ref: "refs/heads/main",
    }, "super-secret-token", {
      fetch: async () => new Response("failed super-secret-token\nsecond line", { status: 403 }),
    }),
    (error) => {
      assert.match(error.message, /HTTP 403/);
      assert.match(error.message, /\[REDACTED\]/);
      assert.equal(error.message.includes("super-secret-token"), false);
      assert.equal(error.message.includes("\n"), false);
      return true;
    },
  );
});

test("SARIF publication requires a fully qualified ref outside pull requests", async () => {
  await assert.rejects(
    () => publishGitHubSarif(report(), {
      repository: "cmahmud/synsec",
      sha: "abcdef1234567890",
    }, "token", { fetch: async () => new Response("", { status: 202 }) }),
    /requires a fully qualified repository ref/,
  );
});
