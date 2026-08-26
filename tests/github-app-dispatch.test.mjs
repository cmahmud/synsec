import assert from "node:assert/strict";
import test from "node:test";
import { dispatchGitHubAppWebhookScan } from "@synsec/github/app-dispatch";

function intake(overrides = {}) {
  return {
    duplicate: false,
    shouldScan: true,
    webhook: {
      event: "push",
      deliveryId: "delivery-1",
      installationId: 7,
      repository: "example/repo",
      headSha: "a".repeat(40),
    },
    ...overrides,
  };
}

test("dispatch requires durable installation authorization before queueing", async () => {
  let enqueued = false;
  const result = await dispatchGitHubAppWebhookScan({
    intake: intake(),
    installationStore: { isRepositoryAllowed: async () => false },
    queue: { enqueue: async () => { enqueued = true; throw new Error("must not enqueue"); } },
  });
  assert.deepEqual(result, { status: "rejected", reason: "installation_not_authorized" });
  assert.equal(enqueued, false);
});

test("dispatch creates only normalized commit-pinned push jobs", async () => {
  let queued;
  const result = await dispatchGitHubAppWebhookScan({
    intake: intake(),
    installationStore: { isRepositoryAllowed: async (id, repository) => id === 7 && repository === "example/repo" },
    queue: { enqueue: async (job) => { queued = job; return { ...job, version: 1, jobId: "f".repeat(32), createdAt: "2026-08-22T18:30:00.000Z", attempts: 0, status: "pending" }; } },
  });
  assert.equal(result.status, "queued");
  assert.deepEqual(queued, {
    deliveryId: "delivery-1",
    installationId: 7,
    repository: "example/repo",
    headSha: "a".repeat(40),
    event: "push",
  });
  assert.equal("cloneUrl" in queued, false);
  assert.equal("token" in queued, false);
});

test("dispatch preserves exact PR base and head provenance", async () => {
  let queued;
  const prIntake = intake({
    webhook: {
      event: "pull_request",
      action: "synchronize",
      deliveryId: "delivery-pr",
      installationId: 8,
      repository: "example/repo",
      headSha: "b".repeat(40),
      baseSha: "c".repeat(40),
      pullRequestNumber: 42,
    },
  });
  const result = await dispatchGitHubAppWebhookScan({
    intake: prIntake,
    installationStore: { isRepositoryAllowed: async () => true },
    queue: { enqueue: async (job) => { queued = job; return { ...job, version: 1, jobId: "e".repeat(32), createdAt: "2026-08-22T18:30:00.000Z", attempts: 0, status: "pending" }; } },
  });
  assert.equal(result.status, "queued");
  assert.equal(queued.headSha, "b".repeat(40));
  assert.equal(queued.baseSha, "c".repeat(40));
  assert.equal(queued.pullRequestNumber, 42);
});

test("duplicates and non-scan events never consult authorization or queue", async () => {
  for (const current of [intake({ duplicate: true }), intake({ shouldScan: false })]) {
    let touched = false;
    const result = await dispatchGitHubAppWebhookScan({
      intake: current,
      installationStore: { isRepositoryAllowed: async () => { touched = true; return true; } },
      queue: { enqueue: async () => { touched = true; throw new Error("must not queue"); } },
    });
    assert.equal(result.status, "ignored");
    assert.equal(touched, false);
  }
});
