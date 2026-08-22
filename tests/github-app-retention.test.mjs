import assert from "node:assert/strict";
import { mkdtemp, utimes } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { FileGitHubScanQueue } from "@synsec/github/scan-queue";
import { pruneGitHubAppFailedJobs } from "@synsec/github/retention";

async function setup(now) {
  const directory = await mkdtemp(join(tmpdir(), "synsec-retention-"));
  return new FileGitHubScanQueue(directory, { now: () => now, leaseMs: 10_000 });
}

async function enqueueFailed(queue, input, modifiedAt) {
  const job = await queue.enqueue(input);
  const leased = await queue.claimNext();
  assert.equal(leased.jobId, job.jobId);
  await queue.fail(job.jobId);
  if (modifiedAt !== undefined) {
    const date = new Date(modifiedAt);
    await utimes(join(queue.directory, `${job.jobId}.json`), date, date);
  }
  return job;
}

test("retention deletes only failed jobs whose terminal record is old", async () => {
  const now = Date.parse("2026-08-22T20:00:00.000Z");
  const queue = await setup(now);
  const oldFailed = await enqueueFailed(queue, {
    deliveryId: "old-failed",
    installationId: 1,
    repository: "o/old",
    headSha: "a".repeat(40),
    event: "push",
    createdAt: new Date(now - 12 * 60 * 60 * 1000).toISOString(),
  }, now - 2 * 60 * 60 * 1000);
  const recentFailed = await enqueueFailed(queue, {
    deliveryId: "recent-failed",
    installationId: 1,
    repository: "o/recent",
    headSha: "b".repeat(40),
    event: "push",
    createdAt: new Date(now - 12 * 60 * 60 * 1000).toISOString(),
  }, now - 30 * 60 * 1000);
  await queue.enqueue({
    deliveryId: "old-pending",
    installationId: 1,
    repository: "o/pending",
    headSha: "c".repeat(40),
    event: "push",
    createdAt: new Date(now - 24 * 60 * 60 * 1000).toISOString(),
  });

  const result = await pruneGitHubAppFailedJobs(queue, {
    now: () => now,
    failedJobRetentionMs: 60 * 60 * 1000,
  });

  assert.deepEqual(result, { inspected: 3, deleted: 1, retainedFailed: 1 });
  const remaining = await queue.list();
  assert.equal(remaining.some((job) => job.jobId === oldFailed.jobId), false);
  assert.equal(remaining.some((job) => job.jobId === recentFailed.jobId), true);
  assert.equal(remaining.some((job) => job.status === "pending"), true);
});

test("retention caps deletions per maintenance pass", async () => {
  const now = Date.parse("2026-08-22T20:00:00.000Z");
  const queue = await setup(now);
  for (let index = 0; index < 3; index += 1) {
    await enqueueFailed(queue, {
      deliveryId: `failed-${index}`,
      installationId: 2,
      repository: `o/r${index}`,
      headSha: `${index + 1}`.repeat(40),
      event: "push",
    }, now - 3 * 60 * 60 * 1000 - index);
  }

  const result = await pruneGitHubAppFailedJobs(queue, {
    now: () => now,
    failedJobRetentionMs: 60 * 60 * 1000,
    maxDeletes: 2,
  });
  assert.deepEqual(result, { inspected: 3, deleted: 2, retainedFailed: 1 });
  assert.equal((await queue.list()).length, 1);
});

test("retention rejects unbounded policy values", async () => {
  const now = Date.parse("2026-08-22T20:00:00.000Z");
  const queue = await setup(now);
  await assert.rejects(
    () => pruneGitHubAppFailedJobs(queue, { failedJobRetentionMs: 1 }),
    /retention must be between/,
  );
  await assert.rejects(
    () => pruneGitHubAppFailedJobs(queue, { maxDeletes: 1001 }),
    /maxDeletes must be between/,
  );
});
