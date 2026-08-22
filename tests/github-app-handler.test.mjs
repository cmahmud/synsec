import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";

import { handleGitHubAppWebhook } from "@synsec/github/app-handler";

const secret = "synsec-app-handler-secret";
const headSha = "0123456789abcdef0123456789abcdef01234567";
const baseSha = "abcdef0123456789abcdef0123456789abcdef01";

function signature(body) {
  return `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
}

class MemoryReplayStore {
  constructor() {
    this.ids = new Set();
  }
  async claim(deliveryId) {
    const accepted = !this.ids.has(deliveryId);
    this.ids.add(deliveryId);
    return { accepted, deliveryId, receivedAt: "2026-08-22T18:40:00.000Z" };
  }
}

class MemoryInstallationStore {
  constructor() {
    this.records = new Map();
    this.putCount = 0;
  }
  async get(id) {
    return this.records.get(id);
  }
  async put(input) {
    this.putCount += 1;
    const record = {
      version: 1,
      installationId: input.installationId,
      accountLogin: input.accountLogin,
      accountType: input.accountType,
      repositorySelection: input.repositorySelection,
      repositories: [...(input.repositories ?? [])].sort(),
      ...(input.suspendedAt ? { suspendedAt: input.suspendedAt } : {}),
      updatedAt: input.updatedAt ?? "2026-08-22T18:40:00.000Z",
    };
    this.records.set(record.installationId, record);
    return record;
  }
  async remove(id) {
    return this.records.delete(id);
  }
  async isRepositoryAllowed(id, repository) {
    const record = this.records.get(id);
    return Boolean(record && !record.suspendedAt && (
      record.repositorySelection === "all" || record.repositories.includes(repository)
    ));
  }
}

class MemoryQueue {
  constructor() {
    this.inputs = [];
  }
  async enqueue(input) {
    this.inputs.push(input);
    return {
      version: 1,
      jobId: "0".repeat(32),
      ...input,
      createdAt: "2026-08-22T18:40:00.000Z",
      attempts: 0,
      status: "pending",
    };
  }
}

test("unified handler synchronizes installation state without enqueueing a scan", async () => {
  const replayStore = new MemoryReplayStore();
  const installationStore = new MemoryInstallationStore();
  const queue = new MemoryQueue();
  const body = Buffer.from(JSON.stringify({
    action: "created",
    installation: {
      id: 42,
      account: { login: "example-org", type: "Organization" },
      repository_selection: "selected",
      suspended_at: null,
    },
    repositories: [{ full_name: "example-org/repo" }],
  }));

  const result = await handleGitHubAppWebhook({
    body,
    signatureHeader: signature(body),
    webhookSecret: secret,
    eventName: "installation",
    deliveryId: "delivery-install-1",
    replayStore,
    installationStore,
    queue,
    now: Date.UTC(2026, 7, 22, 18, 40),
  });

  assert.deepEqual(result, { status: "installation_updated", installationId: 42 });
  assert.equal(await installationStore.isRepositoryAllowed(42, "example-org/repo"), true);
  assert.equal(queue.inputs.length, 0);
});

test("duplicate installation delivery does not mutate authorization state twice", async () => {
  const replayStore = new MemoryReplayStore();
  const installationStore = new MemoryInstallationStore();
  const queue = new MemoryQueue();
  const body = Buffer.from(JSON.stringify({
    action: "created",
    installation: {
      id: 42,
      account: { login: "example-org", type: "Organization" },
      repository_selection: "all",
      suspended_at: null,
    },
  }));
  const input = {
    body,
    signatureHeader: signature(body),
    webhookSecret: secret,
    eventName: "installation",
    deliveryId: "delivery-install-duplicate",
    replayStore,
    installationStore,
    queue,
  };

  assert.equal((await handleGitHubAppWebhook(input)).status, "installation_updated");
  assert.deepEqual(await handleGitHubAppWebhook(input), { status: "ignored", reason: "duplicate" });
  assert.equal(installationStore.putCount, 1);
  assert.equal(queue.inputs.length, 0);
});

test("authorized pull request delivery queues exact commit provenance", async () => {
  const replayStore = new MemoryReplayStore();
  const installationStore = new MemoryInstallationStore();
  const queue = new MemoryQueue();
  await installationStore.put({
    installationId: 7,
    accountLogin: "cmahmud",
    accountType: "User",
    repositorySelection: "selected",
    repositories: ["cmahmud/synsec"],
  });
  const body = Buffer.from(JSON.stringify({
    action: "synchronize",
    installation: { id: 7 },
    repository: { full_name: "cmahmud/synsec", clone_url: "https://attacker.invalid/repo.git" },
    number: 2,
    pull_request: {
      head: { sha: headSha },
      base: { sha: baseSha },
    },
  }));

  const result = await handleGitHubAppWebhook({
    body,
    signatureHeader: signature(body),
    webhookSecret: secret,
    eventName: "pull_request",
    deliveryId: "delivery-pr-1",
    replayStore,
    installationStore,
    queue,
  });

  assert.equal(result.status, "queued");
  assert.equal(queue.inputs.length, 1);
  assert.deepEqual(queue.inputs[0], {
    deliveryId: "delivery-pr-1",
    installationId: 7,
    repository: "cmahmud/synsec",
    headSha,
    event: "pull_request",
    baseSha,
    pullRequestNumber: 2,
  });
  assert.equal(JSON.stringify(queue.inputs[0]).includes("attacker.invalid"), false);
});
