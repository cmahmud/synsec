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
    installationId: 11,
    accountLogin: "sensitive-org",
    accountType: "Organization",
    repositorySelection: "all",
  });
  await installationStore.put({
    installationId: 12,
    accountLogin: "other-org",
    accountType: "Organization",
    repositorySelection: "selected",
    repositories: ["private/example"],
    suspendedAt: "2026-08-22T20:00:00.000Z",
  });

  await queue.enqueue({
    deliveryId: "delivery-sensitive",
    installationId: 11,
    repository: "private/example",
    headSha: "a".repeat(40),
    event: "push",
  });
  await queue.enqueue({
    deliveryId: "delivery-failed",
    installationId: 11,
    repository: "private/failed",
    headSha: "b".repeat(40),
    event: "push",
  });
  const leased = await queue.claimNext();
  await queue.fail(leased.jobId, leased.attempts);

  const status = await buildGitHubAppRuntimeStatus({ installationStore, queue });
  assert.deepEqual(status, {
    installations: { total: 2, active: 1, suspended: 1, allRepositories: 1, selectedRepositories: 1 },
    queue: { total: 2, pending: 1, leased: 0, failed: 1 },
  });

  const serialized = JSON.stringify(status);
  for (const secret of ["sensitive-org", "other-org", "private/example", "delivery-sensitive", "a".repeat(40)]) {
    assert.equal(serialized.includes(secret), false);
  }
});
