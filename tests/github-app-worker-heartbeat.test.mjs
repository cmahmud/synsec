import assert from "node:assert/strict";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { runNextGitHubAppScanJob } from "@synsec/github/app-worker";

const headSha = "0123456789abcdef0123456789abcdef01234567";
const leaseId = "9".repeat(32);

function leasedJob() {
  return {
    version: 1,
    jobId: "8".repeat(32),
    deliveryId: "heartbeat-delivery",
    installationId: 42,
    repository: "cmahmud/synsec",
    headSha,
    event: "push",
    createdAt: "2026-08-22T21:00:00.000Z",
    attempts: 1,
    status: "leased",
    leaseUntil: "2026-08-22T21:05:00.000Z",
    leaseId,
  };
}

function report() {
  return {
    schemaVersion: "1.0",
    reportId: "heartbeat-report",
    generatedAt: "2026-08-22T21:00:01.000Z",
    toolVersion: "0.2.0",
    target: { path: "/tmp/repo", commitSha: headSha },
    scanners: [],
    rawFindingCount: 0,
    findingCount: 0,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
    securityScore: 100,
    findings: [],
  };
}

test("worker renews its exact lease while a scan remains active", async () => {
  const job = leasedJob();
  let renewals = 0;
  let published = 0;
  const queue = {
    leaseMs: 3_000,
    async claimNext() { return job; },
    async assertLease(id, expectedLeaseId) {
      assert.equal(id, job.jobId);
      assert.equal(expectedLeaseId, job.leaseId);
      return job;
    },
    async renew(id, expectedLeaseId) {
      assert.equal(id, job.jobId);
      assert.equal(expectedLeaseId, job.leaseId);
      renewals += 1;
      return job;
    },
    async release() { throw new Error("must not release successful job"); },
    async fail() { throw new Error("must not fail successful job"); },
    async complete(id, expectedLeaseId) {
      assert.equal(id, job.jobId);
      assert.equal(expectedLeaseId, job.leaseId);
      return true;
    },
  };

  const result = await runNextGitHubAppScanJob({
    queue,
    installationStore: { isRepositoryAllowed: async () => true },
    getInstallationToken: async () => "transport-token",
    acquire: async (input) => ({
      repository: input.repository,
      commitSha: input.commitSha,
      workspace: "/tmp/repo",
      cleanup: async () => {},
    }),
    scan: async () => {
      await delay(1_100);
      return report();
    },
    publish: async () => { published += 1; },
  });

  assert.equal(result.status, "completed");
  assert.ok(renewals >= 1);
  assert.equal(published, 1);
});
