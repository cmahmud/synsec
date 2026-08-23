import assert from "node:assert/strict";
import test from "node:test";

import { runNextGitHubAppScanJob } from "@synsec/github/app-worker";

const job = {
  version: 1,
  jobId: "1".repeat(32),
  deliveryId: "delivery-redaction",
  installationId: 123,
  repository: "owner/repo",
  headSha: "a".repeat(40),
  event: "push",
  createdAt: "2026-08-23T00:00:00.000Z",
  attempts: 1,
  status: "leased",
  leaseUntil: "2099-01-01T00:00:00.000Z",
  leaseId: "2".repeat(32),
};

function queue() {
  return {
    async claimNext() { return job; },
    async assertLease() { return job; },
    async release() { return { ...job, status: "pending", leaseUntil: undefined, leaseId: undefined }; },
    async fail() { return { ...job, status: "failed", leaseUntil: undefined, leaseId: undefined }; },
    async complete() { return true; },
  };
}

test("hosted worker redacts credentials from retry errors", async () => {
  const token = `ghp_${"A".repeat(40)}`;
  const password = "super-secret-password";
  const result = await runNextGitHubAppScanJob({
    queue: queue(),
    installationStore: { async isRepositoryAllowed() { return true; } },
    async getInstallationToken() { return token; },
    async acquire() {
      throw new Error(`Authorization: Bearer ${token} url=https://user:${password}@example.test/repo.git`);
    },
    async scan() { throw new Error("scan should not run"); },
    async publish() { throw new Error("publish should not run"); },
  });

  assert.equal(result.status, "retry_scheduled");
  assert.equal(result.error.includes(token), false);
  assert.equal(result.error.includes(password), false);
  assert.match(result.error, /REDACTED/);
});

test("hosted worker redacts credentials when queue release also fails", async () => {
  const token = `github_pat_${"B".repeat(40)}`;
  const failingQueue = queue();
  failingQueue.release = async () => {
    throw new Error(`api_key=${token}`);
  };

  await assert.rejects(
    () => runNextGitHubAppScanJob({
      queue: failingQueue,
      installationStore: { async isRepositoryAllowed() { return true; } },
      async getInstallationToken() { return token; },
      async acquire() { throw new Error(`Authorization: Bearer ${token}`); },
      async scan() { throw new Error("scan should not run"); },
      async publish() { throw new Error("publish should not run"); },
    }),
    (error) => {
      assert.equal(error.message.includes(token), false);
      assert.match(error.message, /REDACTED/);
      return true;
    },
  );
});
