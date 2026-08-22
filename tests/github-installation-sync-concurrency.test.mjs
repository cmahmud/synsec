import assert from "node:assert/strict";
import test from "node:test";

import { synchronizeGitHubInstallationState } from "@synsec/github/installation-sync";

class SnapshotYieldStore {
  constructor() {
    this.records = new Map();
  }

  async get(id) {
    const record = this.records.get(id);
    const snapshot = record ? { ...record, repositories: [...record.repositories] } : undefined;
    await new Promise((resolve) => setImmediate(resolve));
    return snapshot;
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

function addRepository(installationId, repository) {
  return {
    event: "installation_repositories",
    action: "added",
    installationId,
    accountLogin: "example-org",
    accountType: "Organization",
    repositorySelection: "selected",
    repositories: [],
    repositoriesAdded: [repository],
    repositoriesRemoved: [],
  };
}

test("concurrent repository deltas for one installation are serialized within a runtime", async () => {
  const store = new SnapshotYieldStore();
  await store.put({
    installationId: 7,
    accountLogin: "example-org",
    accountType: "Organization",
    repositorySelection: "selected",
    repositories: ["example-org/a"],
    updatedAt: "2026-08-22T18:00:00.000Z",
  });

  await Promise.all([
    synchronizeGitHubInstallationState(addRepository(7, "example-org/b"), store, Date.UTC(2026, 7, 22, 18, 31)),
    synchronizeGitHubInstallationState(addRepository(7, "example-org/c"), store, Date.UTC(2026, 7, 22, 18, 32)),
  ]);

  const record = await store.get(7);
  assert.deepEqual(record.repositories, ["example-org/a", "example-org/b", "example-org/c"]);
});
