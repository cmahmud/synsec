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
  assert.match(leased.leaseId, /^[a-f0-9]{32}$/);
  await queue.release(leased.jobId, leased.leaseId);
  const reclaimed = await queue.claimNext();
  assert.equal(reclaimed.jobId, first.jobId);
  assert.notEqual(reclaimed.leaseId, leased.leaseId);
  assert.equal(await queue.complete(first.jobId, reclaimed.leaseId), true);
  assert.equal((await queue.claimNext()).repository, "o/b");
});

test("concurrent claims on one local queue instance are serialized", async () => {
  const { queue } = await setup({ leaseMs: 10_000 });
  const pending = await queue.enqueue({ deliveryId: "serialized", installationId: 1, repository: "o/r", headSha: "a".repeat(40), event: "push" });
  const results = await Promise.all([queue.claimNext(), queue.claimNext()]);
  const claimed = results.filter(Boolean);
  const idle = results.filter((value) => value === undefined);
  assert.equal(claimed.length, 1);
  assert.equal(idle.length, 1);
  assert.equal(claimed[0].jobId, pending.jobId);
  assert.equal(claimed[0].attempts, 1);
});

test("concurrent duplicate enqueues on one local queue instance persist only one delivery", async () => {
  const { queue } = await setup();
  const input = { deliveryId: "duplicate-race", installationId: 1, repository: "o/r", headSha: "a".repeat(40), event: "push" };
  const results = await Promise.allSettled([queue.enqueue(input), queue.enqueue(input)]);
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  const rejected = results.find((result) => result.status === "rejected");
  assert.ok(rejected);
  assert.match(String(rejected.reason), /already queued/);
  const jobs = await queue.list();
  assert.equal(jobs.length, 1);
  assert.equal(jobs[0].deliveryId, input.deliveryId);
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
  assert.notEqual(second.leaseId, first.leaseId);
});

test("stale lease identities cannot release, fail, or complete reclaimed work", async () => {
  let now = Date.parse("2026-08-22T18:20:00.000Z");
  const { queue } = await setup({ now: () => now, leaseMs: 10_000 });
  await queue.enqueue({ deliveryId: "fence", installationId: 2, repository: "o/r", headSha: "c".repeat(40), event: "push" });
  const first = await queue.claimNext();
  now += 10_001;
  const second = await queue.claimNext();

  await assert.rejects(() => queue.release(first.jobId, first.leaseId), /stale or no longer owned/);
  await assert.rejects(() => queue.fail(first.jobId, first.leaseId), /stale or no longer owned/);
  await assert.rejects(() => queue.complete(first.jobId, first.leaseId), /stale or no longer owned/);
  const current = (await queue.list())[0];
  assert.equal(current.leaseId, second.leaseId);
  assert.equal(current.status, "leased");
});

test("expired lease identities cannot mutate work even before another worker reclaims it", async () => {
  let now = Date.parse("2026-08-22T18:20:00.000Z");
  const { queue } = await setup({ now: () => now, leaseMs: 10_000 });
  await queue.enqueue({ deliveryId: "expired", installationId: 2, repository: "o/r", headSha: "c".repeat(40), event: "push" });
  const leased = await queue.claimNext();
  now += 10_001;
  await assert.rejects(() => queue.assertLease(leased.jobId, leased.leaseId), /lease has expired/);
  await assert.rejects(() => queue.release(leased.jobId, leased.leaseId), /lease has expired/);
});

test("lease renewal extends only the current unique fence", async () => {
  let now = Date.parse("2026-08-22T18:20:00.000Z");
  const { queue } = await setup({ now: () => now, leaseMs: 10_000 });
  await queue.enqueue({ deliveryId: "renew", installationId: 2, repository: "o/r", headSha: "c".repeat(40), event: "push" });
  const leased = await queue.claimNext();
  const initialUntil = leased.leaseUntil;
  now += 4_000;
  const renewed = await queue.renew(leased.jobId, leased.leaseId);
  assert.equal(renewed.leaseId, leased.leaseId);
  assert.ok(Date.parse(renewed.leaseUntil) > Date.parse(initialUntil));
  await assert.rejects(() => queue.renew(leased.jobId, "f".repeat(32)), /stale or no longer owned/);
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
  const failed = await queue.fail(leased.jobId, leased.leaseId);
  assert.equal(failed.status, "failed");
  assert.equal(failed.leaseId, undefined);
  assert.equal(await queue.claimNext(), undefined);
  assert.equal((await queue.list())[0].status, "failed");
});
