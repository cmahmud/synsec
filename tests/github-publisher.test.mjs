import test from "node:test";
import assert from "node:assert/strict";

import { publishGitHubCheck, toGitHubCheckRunRequest } from "../packages/github/dist/publisher.js";

const context = { repository: "cmahmud/synsec", sha: "head-sha" };
const check = {
  name: "SynSec repository security",
  headSha: "head-sha",
  conclusion: "failure",
  output: {
    title: "SynSec found findings at or above high",
    summary: "High: **1**",
    text: "Report report-1 scanned changed files.",
    annotations: [{
      path: "src/app.ts",
      start_line: 4,
      end_line: 4,
      annotation_level: "failure",
      title: "[HIGH] Unsafe input",
      message: "Unsafe input reaches a sink.",
    }],
  },
};

test("toGitHubCheckRunRequest emits a completed check-run payload", () => {
  assert.deepEqual(toGitHubCheckRunRequest(check), {
    name: check.name,
    head_sha: "head-sha",
    status: "completed",
    conclusion: "failure",
    output: check.output,
  });
});

test("publishGitHubCheck posts only to the fixed GitHub Checks API endpoint", async () => {
  let request;
  const fakeFetch = async (url, init) => {
    request = { url, init };
    return new Response(JSON.stringify({
      id: 123,
      html_url: "https://github.com/cmahmud/synsec/runs/123",
      status: "completed",
      conclusion: "failure",
    }), { status: 201, headers: { "content-type": "application/json" } });
  };

  const published = await publishGitHubCheck(check, context, "installation-token", { fetch: fakeFetch });
  assert.equal(request.url, "https://api.github.com/repos/cmahmud/synsec/check-runs");
  assert.equal(request.init.method, "POST");
  assert.equal(request.init.redirect, "error");
  assert.equal(request.init.headers.Authorization, "Bearer installation-token");
  assert.equal(JSON.parse(request.init.body).head_sha, "head-sha");
  assert.deepEqual(published, {
    id: 123,
    htmlUrl: "https://github.com/cmahmud/synsec/runs/123",
    status: "completed",
    conclusion: "failure",
  });
});

test("publishGitHubCheck fails closed on invalid repository or missing token", async () => {
  await assert.rejects(() => publishGitHubCheck(check, { repository: "not a repo", sha: "x" }, "token", { fetch: async () => { throw new Error("should not run"); } }), /Invalid GitHub repository/);
  await assert.rejects(() => publishGitHubCheck(check, context, "   ", { fetch: async () => { throw new Error("should not run"); } }), /token is required/);
});

test("publisher surfaces API errors without including the bearer token", async () => {
  const secret = "very-secret-token";
  const fakeFetch = async () => new Response(JSON.stringify({ message: "Resource not accessible by integration" }), { status: 403 });
  await assert.rejects(
    () => publishGitHubCheck(check, context, secret, { fetch: fakeFetch }),
    (error) => {
      assert.match(error.message, /HTTP 403/);
      assert.equal(error.message.includes(secret), false);
      return true;
    },
  );
});
