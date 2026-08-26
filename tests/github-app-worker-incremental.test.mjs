import assert from "node:assert/strict";
import test from "node:test";
import { runConfiguredGitHubAppWorkerOnce } from "@synsec/github/app-worker-runner";

const headSha = "0123456789abcdef0123456789abcdef01234567";
const baseSha = "abcdef0123456789abcdef0123456789abcdef01";
const leaseId = "e".repeat(32);

function report(commitSha, baseline = false, scope) {
  return {
    schemaVersion: "1.0",
    reportId: `report-${commitSha.slice(0, 8)}`,
    generatedAt: "2026-08-22T19:00:00.000Z",
    toolVersion: "0.2.0",
    target: { path: "/tmp/repo", commitSha },
    scanners: [],
    rawFindingCount: 0,
    findingCount: 0,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
    securityScore: 100,
    findings: [],
    ...(scope ? { scope } : {}),
    ...(baseline ? { baseline: { new: [], fixed: [], persisting: [] } } : {}),
  };
}

function job() {
  return {
    version: 1,
    jobId: "c".repeat(32),
    deliveryId: "delivery-incremental-worker",
    installationId: 42,
    repository: "cmahmud/synsec",
    headSha,
    event: "pull_request",
    baseSha,
    pullRequestNumber: 2,
    createdAt: "2026-08-22T19:00:00.000Z",
    attempts: 1,
    status: "leased",
    leaseUntil: "2026-08-22T19:05:00.000Z",
    leaseId,
  };
}

function queueFor(jobValue) {
  return {
    async claimNext() { return jobValue; },
    async assertLease(id, expectedLeaseId) {
      assert.equal(id, jobValue.jobId);
      assert.equal(expectedLeaseId, jobValue.leaseId);
      return jobValue;
    },
    async release() { throw new Error("must not release successful job"); },
    async fail() { throw new Error("must not fail successful job"); },
    async complete(id, expectedLeaseId) {
      assert.equal(id, jobValue.jobId);
      assert.equal(expectedLeaseId, jobValue.leaseId);
      return true;
    },
  };
}

function acquisition(input) {
  return {
    repository: input.repository,
    commitSha: input.commitSha,
    workspace: "/tmp/head",
    base: { commitSha: input.baseCommitSha, workspace: "/tmp/base" },
    cleanup: async () => {},
  };
}

const checkFetch = async (url) => {
  if (url.endsWith("/check-runs")) return new Response(JSON.stringify({ id: 1 }), { status: 201 });
  if (url.endsWith("/code-scanning/sarifs")) return new Response(JSON.stringify({ id: "sarif" }), { status: 202 });
  throw new Error(`unexpected URL ${url}`);
};

test("hosted PR worker passes exact changed paths and base SHA into the head scan", async () => {
  const scanInputs = [];
  const result = await runConfiguredGitHubAppWorkerOnce({
    queue: queueFor(job()),
    installationStore: { isRepositoryAllowed: async () => true },
    config: { scanners: ["opengrep"], parallelism: 1 },
    getInstallationToken: async () => "token",
    acquire: async (input) => acquisition(input),
    deriveChangedFiles: async () => ({
      mode: "changed-files", reason: "exact-tree-diff", changedFiles: ["src/a.ts", "src/b.ts"], deletedFiles: [],
      interpretation: "exact-commit-tree-comparison-with-conservative-full-scan-fallback",
    }),
    scan: async (input) => {
      scanInputs.push(input);
      const isBase = input.rootPath === "/tmp/base";
      return {
        report: report(isBase ? baseSha : headSha, Boolean(input.baseline), input.changedOnly
          ? { mode: "changed-files", baseRef: input.changedBase, changedFiles: [...input.changedFiles] }
          : { mode: "repository" }),
        repositoryIndex: { schemaVersion: 1, generatedAt: "2026-08-22T19:00:00.000Z", indexedFileCount: 0, moduleEdges: [], routes: [], authSignals: [], sinks: [] },
        statuses: [], failures: [], shouldFail: false,
      };
    },
    fetch: checkFetch,
  });

  assert.equal(result.status, "completed");
  assert.equal(scanInputs.length, 2);
  assert.equal(scanInputs[0].changedOnly, false);
  assert.equal(scanInputs[1].changedOnly, true);
  assert.equal(scanInputs[1].changedBase, baseSha);
  assert.deepEqual(scanInputs[1].changedFiles, ["src/a.ts", "src/b.ts"]);
});

test("hosted PR worker keeps SARIF publication on a full head scan even when an exact diff exists", async () => {
  const scanInputs = [];
  const result = await runConfiguredGitHubAppWorkerOnce({
    queue: queueFor(job()),
    installationStore: { isRepositoryAllowed: async () => true },
    config: { scanners: ["opengrep"], parallelism: 1 },
    getInstallationToken: async () => "token",
    acquire: async (input) => acquisition(input),
    deriveChangedFiles: async () => ({
      mode: "changed-files", reason: "exact-tree-diff", changedFiles: ["src/a.ts"], deletedFiles: [],
      interpretation: "exact-commit-tree-comparison-with-conservative-full-scan-fallback",
    }),
    scan: async (input) => {
      scanInputs.push(input);
      const isBase = input.rootPath === "/tmp/base";
      return {
        report: report(isBase ? baseSha : headSha, Boolean(input.baseline), { mode: "repository" }),
        repositoryIndex: { schemaVersion: 1, generatedAt: "2026-08-22T19:00:00.000Z", indexedFileCount: 0, moduleEdges: [], routes: [], authSignals: [], sinks: [] },
        statuses: [], failures: [], shouldFail: false,
      };
    },
    publishSarif: true,
    fetch: checkFetch,
  });

  assert.equal(result.status, "completed");
  assert.equal(scanInputs[1].changedOnly, false);
  assert.equal(scanInputs[1].changedFiles, undefined);
});
