import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";

import {
  parseVerifiedGitHubInstallationStateEvent,
  synchronizeGitHubInstallationState,
} from "@synsec/github/installation-sync";

const secret = "synsec-installation-sync-secret";

function signature(body) {
  return `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
}

class MemoryInstallationStore {
  constructor() {
    this.records = new Map();
  }
  async get(id) {
    return this.records.get(id);
  }
  async put(input) {
    const record = {
      version: 1,
      installationId: input.installationId,
      accountLogin: input.accountLogin,
      accountType: input.accountType,
      repositorySelection: input.repositorySelection,
      repositories: [...(input.repositories ?? [])].sort(),
      ...(input.suspendedAt ? { suspendedAt: input.suspendedAt } : {}),
      updatedAt: input.updatedAt ?? new Date().toISOString(),
    };
    this.records.set(record.installationId, record);
    return record;
  }
  async remove(id) {
    return this.records.delete(id);
  }
}

test("verified installation creation normalizes only authorization state", async () => {
  const body = Buffer.from(JSON.stringify({
    action: "created",
    installation: {
      id: 42,
      account: { login: "example-org", type: "Organization" },
      repository_selection: "selected",
      suspended_at: null,
      access_tokens_url: "https://attacker.invalid/token",
    },
    repositories: [
      { full_name: "example-org/b", clone_url: "https://attacker.invalid/b.git" },
      { full_name: "example-org/a" },
    ],
  }));

  const event = parseVerifiedGitHubInstallationStateEvent({
    body,
    signatureHeader: signature(body),
    webhookSecret: secret,
    eventName: "installation",
  });
  assert.deepEqual(event, {
    event: "installation",
    action: "created",
    installationId: 42,
    accountLogin: "example-org",
    accountType: "Organization",
    repositorySelection: "selected",
    repositories: ["example-org/a", "example-org/b"],
    repositoriesAdded: [],
    repositoriesRemoved: [],
  });

  const store = new MemoryInstallationStore();
  const result = await synchronizeGitHubInstallationState(event, store, Date.UTC(2026, 7, 22, 18, 30));
  assert.equal(result.status, "updated");
  assert.equal(await store.get(42).then((record) => record.repositories.includes("example-org/a")), true);
  assert.equal(JSON.stringify(await store.get(42)).includes("attacker.invalid"), false);
});

test("new installation creation replaces stale selected repository authorization", async () => {
  const store = new MemoryInstallationStore();
  await store.put({
    installationId: 42,
    accountLogin: "example-org",
    accountType: "Organization",
    repositorySelection: "selected",
    repositories: ["example-org/stale-repo"],
  });

  const result = await synchronizeGitHubInstallationState({
    event: "installation",
    action: "created",
    installationId: 42,
    accountLogin: "example-org",
    accountType: "Organization",
    repositorySelection: "selected",
    repositories: [],
    repositoriesAdded: [],
    repositoriesRemoved: [],
  }, store, Date.UTC(2026, 7, 22, 18, 30));

  assert.equal(result.status, "updated");
  assert.deepEqual(result.record.repositories, []);
});

test("repository-selection deltas preserve bounded selected authorization", async () => {
  const store = new MemoryInstallationStore();
  await store.put({
    installationId: 7,
    accountLogin: "example-org",
    accountType: "Organization",
    repositorySelection: "selected",
    repositories: ["example-org/a", "example-org/b"],
    updatedAt: "2026-08-22T18:00:00.000Z",
  });
  const event = {
    event: "installation_repositories",
    action: "added",
    installationId: 7,
    accountLogin: "example-org",
    accountType: "Organization",
    repositorySelection: "selected",
    repositories: [],
    repositoriesAdded: ["example-org/c"],
    repositoriesRemoved: ["example-org/a"],
  };
  const result = await synchronizeGitHubInstallationState(event, store, Date.UTC(2026, 7, 22, 18, 31));
  assert.equal(result.status, "updated");
  assert.deepEqual(result.record.repositories, ["example-org/b", "example-org/c"]);
});

test("suspend and unsuspend events fail closed and preserve selected repositories", async () => {
  const store = new MemoryInstallationStore();
  await store.put({
    installationId: 9,
    accountLogin: "example-org",
    accountType: "Organization",
    repositorySelection: "selected",
    repositories: ["example-org/repo"],
  });
  const base = {
    event: "installation",
    installationId: 9,
    accountLogin: "example-org",
    accountType: "Organization",
    repositorySelection: "selected",
    repositories: [],
    repositoriesAdded: [],
    repositoriesRemoved: [],
  };
  const suspended = await synchronizeGitHubInstallationState({ ...base, action: "suspend" }, store, Date.UTC(2026, 7, 22, 18, 32));
  assert.ok(suspended.record.suspendedAt);
  assert.deepEqual(suspended.record.repositories, ["example-org/repo"]);
  const unsuspended = await synchronizeGitHubInstallationState({ ...base, action: "unsuspend" }, store, Date.UTC(2026, 7, 22, 18, 33));
  assert.equal(unsuspended.record.suspendedAt, undefined);
  assert.deepEqual(unsuspended.record.repositories, ["example-org/repo"]);
});

test("deleted installations are removed without requiring payload account metadata", async () => {
  const store = new MemoryInstallationStore();
  await store.put({ installationId: 3, accountLogin: "owner", accountType: "User", repositorySelection: "all" });
  const result = await synchronizeGitHubInstallationState({
    event: "installation",
    action: "deleted",
    installationId: 3,
    repositories: [],
    repositoriesAdded: [],
    repositoriesRemoved: [],
  }, store);
  assert.deepEqual(result, { status: "removed", installationId: 3, existed: true });
  assert.equal(await store.get(3), undefined);
});

test("installation synchronization rejects unsafe repositories, unsigned payloads, and inconsistent deltas", async () => {
  const unsafeBody = Buffer.from(JSON.stringify({
    action: "created",
    installation: {
      id: 1,
      account: { login: "owner", type: "User" },
      repository_selection: "selected",
    },
    repositories: [{ full_name: "github.com@attacker.invalid/repo" }],
  }));
  assert.throws(() => parseVerifiedGitHubInstallationStateEvent({
    body: unsafeBody,
    signatureHeader: signature(unsafeBody),
    webhookSecret: secret,
    eventName: "installation",
  }), /unsafe/);
  assert.throws(() => parseVerifiedGitHubInstallationStateEvent({
    body: unsafeBody,
    signatureHeader: "sha256=" + "0".repeat(64),
    webhookSecret: secret,
    eventName: "installation",
  }), /signature verification failed/);

  const store = new MemoryInstallationStore();
  await assert.rejects(() => synchronizeGitHubInstallationState({
    event: "installation_repositories",
    action: "added",
    installationId: 999,
    accountLogin: "owner",
    accountType: "User",
    repositorySelection: "selected",
    repositories: [],
    repositoriesAdded: ["owner/repo"],
    repositoriesRemoved: [],
  }, store), /before installation state was initialized/);
});
