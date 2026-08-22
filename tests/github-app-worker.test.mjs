import assert from "node:assert/strict";
import test from "node:test";

import { runNextGitHubAppScanJob } from "@synsec/github/app-worker";

const headSha = "0123456789abcdef0123456789abcdef01234567";

function job() {
  return {
    version: 1,
    jobId: "a".repeat(32),
    deliveryId: "delivery-worker-1",
    installationId: 42,
    repository: "cmahmud/synsec",
    headSha,
    event: "push",
    createdAt: "2026-08-22T18:45:00.000Z",
    attempts: 1,
    status: "leased",
    leaseUntil: "2026-08-22T18:50:00.000Z",
  };
}

function report(commitSha = headSha) {
  return {
    schemaVersion: "1.0",
    reportId: "report-1",
    generatedAt: "2026-08-22T18:46:00.000Z",
    toolVersion: "0.2.0",
    target: { path: "/tmp/repo", commitSha },
    scanners: [],
    rawFindingCount: 0,
    findingCount: 0,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
    securityScore: 100,
    findings: [],
  };
}

class MemoryQueue {
  constructor(next = job()) {
    this.next = next;
    this.completed = [];
    this.released = [];
    this.failed = [];
  }
  async claimNext() {
    const next = this.next;
    this.next = undefined;
    return next;
  }
  async release(id) {
    this.released.push(id);
    return { ...job(), status: "pending", leaseUntil: undefined };
  }
  async fail(id) {
    this.failed.push(id);
    return { ...job(), status: "failed", leaseUntil: undefined };
  }
  async complete(id) {
    this.completed.push(id);
    return true;
  }
}

test("worker returns idle when no queued job is available", async () => {
  const queue = new MemoryQueue(null);
  const result = await runNextGitHubAppScanJob({
    queue,
    installationStore: { isRepositoryAllowed: async () => true },
    getInstallationToken: async () => "token",
    acquire: async () => { throw new Error("must not acquire"); },
    scan: async () => { throw new Error("must not scan"); },
    publish: async () => { throw new Error("must not publish"); },
  });
  assert.deepEqual(result, { status: "idle" });
});

test("worker rechecks authorization before obtaining credentials or repository content", async () => {
  const queue = new MemoryQueue();
  let tokenCalls = 0;
  let acquisitionCalls = 0;
  const result = await runNextGitHubAppScanJob({
    queue,
    installationStore: { isRepositoryAllowed: async () => false },
    getInstallationToken: async () => { tokenCalls += 1; return "token"; },
    acquire: async () => { acquisitionCalls += 1; throw new Error("must not acquire"); },
    scan: async () => { throw new Error("must not scan"); },
    publish: async () => { throw new Error("must not publish"); },
  });
  assert.equal(result.status, "revoked");
  assert.deepEqual(queue.failed, ["a".repeat(32)]);
  assert.equal(tokenCalls, 0);
  assert.equal(acquisitionCalls, 0);
});

test("worker isolates transport credentials from scanning and publishes only a commit-bound report", async () => {
  const queue = new MemoryQueue();
  const tokenPurposes = [];
  const acquisitionTokens = [];
  const publicationTokens = [];
  let cleanupCalls = 0;
  let scannedWorkspace;
  const result = await runNextGitHubAppScanJob({
    queue,
    installationStore: { isRepositoryAllowed: async () => true },
    getInstallationToken: async (_installationId, purpose) => {
      tokenPurposes.push(purpose);
      return purpose === "acquire" ? "acquisition-secret" : "publication-secret";
    },
    acquire: async (input) => {
      acquisitionTokens.push(input.installationToken);
      return {
        repository: input.repository,
        commitSha: input.commitSha,
        workspace: "/tmp/synsec-worker-repo",
        cleanup: async () => { cleanupCalls += 1; },
      };
    },
    scan: async (_job, workspace) => {
      scannedWorkspace = workspace;
      return report();
    },
    publish: async (_job, _report, token) => {
      publicationTokens.push(token);
    },
  });

  assert.equal(result.status, "completed");
  assert.deepEqual(tokenPurposes, ["acquire", "publish"]);
  assert.deepEqual(acquisitionTokens, ["acquisition-secret"]);
  assert.deepEqual(publicationTokens, ["publication-secret"]);
  assert.equal(scannedWorkspace, "/tmp/synsec-worker-repo");
  assert.deepEqual(queue.completed, ["a".repeat(32)]);
  assert.deepEqual(queue.released, []);
  assert.equal(cleanupCalls, 1);
});

test("worker refuses stale scan output, cleans the workspace, and schedules bounded queue retry", async () => {
  const queue = new MemoryQueue();
  let publishCalls = 0;
  let cleanupCalls = 0;
  const result = await runNextGitHubAppScanJob({
    queue,
    installationStore: { isRepositoryAllowed: async () => true },
    getInstallationToken: async () => "token",
    acquire: async (input) => ({
      repository: input.repository,
      commitSha: input.commitSha,
      workspace: "/tmp/synsec-worker-repo",
      cleanup: async () => { cleanupCalls += 1; },
    }),
    scan: async () => report("abcdef0123456789abcdef0123456789abcdef01"),
    publish: async () => { publishCalls += 1; },
  });

  assert.equal(result.status, "retry_scheduled");
  assert.match(result.error, /report commit does not match/);
  assert.equal(publishCalls, 0);
  assert.deepEqual(queue.released, ["a".repeat(32)]);
  assert.deepEqual(queue.completed, []);
  assert.equal(cleanupCalls, 1);
});
