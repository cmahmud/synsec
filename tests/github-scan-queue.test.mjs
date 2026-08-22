import assert from "node:assert/strict";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { FileGitHubScanQueue } from "@synsec/github/scan-queue";

async function setup(options = {}) {
  const directory = await mkdtemp(join(tmpdir(), "synsec-queue-"));
  return { directory, queue: new FileGitHubScanQueue(directory, options) };
}

test("scan queue persists commit-pinned repository jobs without credentials", async () => {
  const { directory, queue } = await setup({ now: () => Date.parse("2026-08-22T18:20:00.000Z") });
  const job = await queue.enqueue({
    deliveryId: "delivery-1",
    installationId: 44,
    repository: "example/repo",
    headSha: "a".repeat(40),
    event: "pull_request",
    baseSha: "b".repeat(40),
    pullRequestNumber: 12,
  });
  const raw = await readFile(join(directory, `${job.jobId}.json`), "utf8");
  assert.equal(raw.includes("token"), false);
  assert.equal(raw.includes("clone_url"), false);
  assert.equal(raw.includes("privateKey"), false);
  if (process.platform !== "win32") assert.equal((await stat(join(directory, `${job.jobId}.json`))).mode & 0o777, 0o600);
});

test("scan queue leases, releases, and completes work deterministically", async () => {
  let now = Date.parse("2026-08-22T18:20:00.000Z");
  const { queue } = await setup({ now: () => now, leaseMs: 10_000 });
  const first = await queue.enqueue({ deliveryId: "a", installationId: 1, repository: "o/a", headSha: "a".repeat(40), event: "push" });
  now += 1;
  await queue.enqueue({ deliveryId: "b", installationId: 1, repository: "o/b", headSha: "b".repeat(40), event: "push" });
  const leased = await queue.claimNext();
  assert.equal(leased.jobId, first.jobId);
  assert.equal(leased.attempts, 1);
  await queue.release(leased.jobId, leased.attempts);
  const reclaimed = await queue.claimNext();
  assert.equal(reclaimed.jobId, first.jobId);
  assert.equal(await queue.complete(first.jobId, reclaimed.attempts), true);
  assert.equal((await queue.claimNext()).repository, "o/b");
});

test("expired leases can be reclaimed but active leases cannot", async () => {
  let now = Date.parse("2026-08-22T18:20:00.000Z");
  const { queue } = await setup({ now: () => now, leaseMs: 10_000 });
  await queue.enqueue({ deliveryId: "lease", installationId: 2, repository: "o/r", headSha: "c".repeat(40), event: "push" });
  const first = await queue.claimNext();
  assert.equal(await queue.claimNext(), undefined);
  now += 10_001;
  const second = await queue.claimNext();
  assert.equal(second.jobId, first.jobId);
  assert.equal(second.attempts, 2);
});

test("stale lease generations cannot release, fail, or complete reclaimed work", async () => {
  let now = Date.parse("2026-08-22T18:20:00.000Z");
  const { queue } = await setup({ now: () => now, leaseMs: 10_000 });
  await queue.enqueue({ deliveryId: "fence", installationId: 2, repository: "o/r", headSha: "c".repeat(40), event: "push" });
  const first = await queue.claimNext();
  now += 10_001;
  const second = await queue.claimNext();
  assert.equal(second.attempts, first.attempts + 1);

  await assert.rejects(() => queue.release(first.jobId, first.attempts), /stale or no longer owned/);
  await assert.rejects(() => queue.fail(first.jobId, first.attempts), /stale or no longer owned/);
  await assert.rejects(() => queue.complete(first.jobId, first.attempts), /stale or no longer owned/);
  assert.equal((await queue.list())[0].attempts, second.attempts);
  assert.equal((await queue.list())[0].status, "leased");
});

test("expired lease generations cannot mutate work even before another worker reclaims it", async () => {
  let now = Date.parse("2026-08-22T18:20:00.000Z");
  const { queue } = await setup({ now: () => now, leaseMs: 10_000 });
  await queue.enqueue({ deliveryId: "expired", installationId: 2, repository: "o/r", headSha: "c".repeat(40), event: "push" });
  const leased = await queue.claimNext();
  now += 10_001;
  await assert.rejects(() => queue.assertLease(leased.jobId, leased.attempts), /lease has expired/);
  await assert.rejects(() => queue.release(leased.jobId, leased.attempts), /lease has expired/);
});

test("queue rejects duplicate deliveries and malformed PR jobs", async () => {
  const { queue } = await setup();
  await queue.enqueue({ deliveryId: "same", installationId: 3, repository: "o/r", headSha: "d".repeat(40), event: "push" });
  await assert.rejects(() => queue.enqueue({ deliveryId: "same", installationId: 3, repository: "o/r2", headSha: "e".repeat(40), event: "push" }), /already queued/);
  await assert.rejects(() => queue.enqueue({ deliveryId: "pr", installationId: 3, repository: "o/r", headSha: "e".repeat(40), event: "pull_request" }), /require base SHA/);
});

test("failed jobs are retained and not claimed again", async () => {
  const { queue } = await setup();
  await queue.enqueue({ deliveryId: "fail", installationId: 4, repository: "o/r", headSha: "f".repeat(40), event: "push" });
  const leased = await queue.claimNext();
  const failed = await queue.fail(leased.jobId, leased.attempts);
  assert.equal(failed.status, "failed");
  assert.equal(await queue.claimNext(), undefined);
  assert.equal((await queue.list())[0].status, "failed");
});
