import assert from "node:assert/strict";
import test from "node:test";

import { runConfiguredGitHubAppWorkerOnce } from "@synsec/github/app-worker-runner";

const headSha = "0123456789abcdef0123456789abcdef01234567";

function report() {
  return {
    schemaVersion: "1.0",
    reportId: "configured-worker-report",
    generatedAt: "2026-08-22T19:00:00.000Z",
    toolVersion: "0.2.0",
    target: { path: "/tmp/acquired", commitSha: headSha },
    scanners: [],
    rawFindingCount: 0,
    findingCount: 0,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
    securityScore: 100,
    findings: [],
  };
}

function leasedPrJob() {
  return {
    version: 1,
    jobId: "b".repeat(32),
    deliveryId: "delivery-configured-worker",
    installationId: 42,
    repository: "cmahmud/synsec",
    headSha,
    event: "pull_request",
    baseSha: "abcdef0123456789abcdef0123456789abcdef01",
    pullRequestNumber: 2,
    createdAt: "2026-08-22T19:00:00.000Z",
    attempts: 1,
    status: "leased",
    leaseUntil: "2026-08-22T19:05:00.000Z",
  };
}

test("configured worker runs the existing scan engine path and publishes check plus optional SARIF", async () => {
  const job = leasedPrJob();
  const completed = [];
  const scanInputs = [];
  const tokenPurposes = [];
  const requests = [];
  let cleanupCalls = 0;
  const queue = {
    async claimNext() { return job; },
    async release() { throw new Error("must not release successful job"); },
    async fail() { throw new Error("must not fail successful job"); },
    async complete(id) { completed.push(id); return true; },
  };
  const fakeFetch = async (url, init) => {
    requests.push({ url, init });
    if (url.endsWith("/check-runs")) {
      return new Response(JSON.stringify({ id: 123, status: "completed", conclusion: "success" }), { status: 201 });
    }
    if (url.endsWith("/code-scanning/sarifs")) {
      return new Response(JSON.stringify({ id: "sarif-upload-1" }), { status: 202 });
    }
    throw new Error(`unexpected publication URL: ${url}`);
  };

  const result = await runConfiguredGitHubAppWorkerOnce({
    queue,
    installationStore: { isRepositoryAllowed: async () => true },
    config: { scanners: ["opengrep"], parallelism: 1 },
    getInstallationToken: async (_installationId, purpose) => {
      tokenPurposes.push(purpose);
      return purpose === "acquire" ? "acquire-token" : "publish-token";
    },
    acquire: async (input) => ({
      repository: input.repository,
      commitSha: input.commitSha,
      workspace: "/tmp/acquired",
      cleanup: async () => { cleanupCalls += 1; },
    }),
    scan: async (input) => {
      scanInputs.push(input);
      return {
        report: report(),
        repositoryIndex: { version: 1, root: "/tmp/acquired", files: [] },
        statuses: [],
        failures: [],
        shouldFail: false,
      };
    },
    publishSarif: true,
    fetch: fakeFetch,
  });

  assert.equal(result.status, "completed");
  assert.deepEqual(completed, [job.jobId]);
  assert.equal(scanInputs.length, 1);
  assert.equal(scanInputs[0].rootPath, "/tmp/acquired");
  assert.equal(scanInputs[0].changedOnly, false);
  assert.deepEqual(tokenPurposes, ["acquire", "publish"]);
  assert.equal(requests.length, 2);
  assert.equal(requests[0].url, "https://api.github.com/repos/cmahmud/synsec/check-runs");
  assert.equal(requests[1].url, "https://api.github.com/repos/cmahmud/synsec/code-scanning/sarifs");
  const checkBody = JSON.parse(requests[0].init.body);
  assert.equal(checkBody.head_sha, headSha);
  const sarifBody = JSON.parse(requests[1].init.body);
  assert.equal(sarifBody.commit_sha, headSha);
  assert.equal(sarifBody.ref, "refs/pull/2/head");
  assert.equal(requests.some((request) => request.url.includes("attacker.invalid")), false);
  assert.equal(cleanupCalls, 1);
});
