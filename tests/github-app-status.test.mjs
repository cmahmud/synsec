import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { FileGitHubInstallationStore } from "@synsec/github/installation-store";
import { FileGitHubScanQueue } from "@synsec/github/scan-queue";
import { buildGitHubAppRuntimeStatus } from "@synsec/github/app-status";

test("runtime status exposes aggregate installation and queue posture only", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-status-"));
  const installationStore = new FileGitHubInstallationStore(join(root, "installations"));
  const queue = new FileGitHubScanQueue(join(root, "queue"));

  await installationStore.put({
    installationId: 11, accountLogin: "sensitive-org", accountType: "Organization", repositorySelection: "all",
  });
  await installationStore.put({
    installationId: 12, accountLogin: "other-org", accountType: "Organization", repositorySelection: "selected",
    repositories: ["private/example"], suspendedAt: "2026-08-22T20:00:00.000Z",
  });

  await queue.enqueue({ deliveryId: "delivery-sensitive", installationId: 11, repository: "private/example", headSha: "a".repeat(40), event: "push" });
  await queue.enqueue({ deliveryId: "delivery-failed", installationId: 11, repository: "private/failed", headSha: "b".repeat(40), event: "push" });
  const leased = await queue.claimNext();
  await queue.fail(leased.jobId, leased.leaseId);

  const status = await buildGitHubAppRuntimeStatus({ installationStore, queue });
  assert.deepEqual(status, {
    installations: { total: 2, active: 1, suspended: 1, allRepositories: 1, selectedRepositories: 1 },
    queue: { total: 2, pending: 1, leased: 0, expiredLeases: 0, failed: 1 },
  });

  const serialized = JSON.stringify(status);
  for (const secret of ["sensitive-org", "other-org", "private/example", "delivery-sensitive", "a".repeat(40)]) {
    assert.equal(serialized.includes(secret), false);
  }
});

test("runtime status surfaces expired leases without exposing job identity", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-status-expired-"));
  const now = Date.parse("2026-08-22T21:00:00.000Z");
  const installationStore = new FileGitHubInstallationStore(join(root, "installations"));
  const queue = new FileGitHubScanQueue(join(root, "queue"), { now: () => now - 20_000, leaseMs: 10_000 });

  await queue.enqueue({
    deliveryId: "expired-sensitive-delivery",
    installationId: 77,
    repository: "private/expired-repository",
    headSha: "c".repeat(40),
    event: "push",
  });
  const leased = await queue.claimNext();
  assert.equal(leased.status, "leased");

  const status = await buildGitHubAppRuntimeStatus({ installationStore, queue, now: () => now });
  assert.deepEqual(status.queue, { total: 1, pending: 0, leased: 1, expiredLeases: 1, failed: 0 });
  const serialized = JSON.stringify(status);
  assert.equal(serialized.includes("private/expired-repository"), false);
  assert.equal(serialized.includes("expired-sensitive-delivery"), false);
  assert.equal(serialized.includes(leased.jobId), false);
  assert.equal(serialized.includes(leased.leaseId), false);
});
