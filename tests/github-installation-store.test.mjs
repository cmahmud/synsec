import assert from "node:assert/strict";
import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { FileGitHubInstallationStore } from "@synsec/github/installation-store";

async function withStore(fn) {
  const directory = await mkdtemp(join(tmpdir(), "synsec-installations-"));
  return fn(new FileGitHubInstallationStore(directory), directory);
}

test("installation store persists only bounded authorization metadata", async () => {
  await withStore(async (store, directory) => {
    const record = await store.put({
      installationId: 42,
      accountLogin: "example-org",
      accountType: "Organization",
      repositorySelection: "selected",
      repositories: ["example-org/b", "example-org/a", "example-org/a"],
      updatedAt: "2026-08-22T18:00:00.000Z",
    });
    assert.deepEqual(record.repositories, ["example-org/a", "example-org/b"]);
    assert.equal(await store.isRepositoryAllowed(42, "example-org/a"), true);
    assert.equal(await store.isRepositoryAllowed(42, "example-org/c"), false);

    const stored = await readFile(join(directory, "42.json"), "utf8");
    assert.equal(stored.includes("token"), false);
    assert.equal(stored.includes("privateKey"), false);
    assert.equal(stored.includes("clone_url"), false);
    if (process.platform !== "win32") assert.equal((await stat(join(directory, "42.json"))).mode & 0o777, 0o600);
  });
});

test("all-repository installations do not persist an enumerated target list", async () => {
  await withStore(async (store) => {
    await assert.rejects(() => store.put({
      installationId: 1,
      accountLogin: "owner",
      accountType: "User",
      repositorySelection: "all",
      repositories: ["owner/repo"],
    }), /must not persist/);

    await store.put({
      installationId: 1,
      accountLogin: "owner",
      accountType: "User",
      repositorySelection: "all",
    });
    assert.equal(await store.isRepositoryAllowed(1, "owner/anything"), true);
  });
});

test("suspended and removed installations cannot authorize scans", async () => {
  await withStore(async (store) => {
    await store.put({
      installationId: 9,
      accountLogin: "example",
      accountType: "Organization",
      repositorySelection: "selected",
      repositories: ["example/repo"],
      suspendedAt: "2026-08-22T18:01:00.000Z",
    });
    assert.equal(await store.isRepositoryAllowed(9, "example/repo"), false);
    assert.equal(await store.remove(9), true);
    assert.equal(await store.remove(9), false);
    assert.equal(await store.get(9), undefined);
  });
});

test("installation store fails closed on corrupt or mismatched records", async () => {
  await withStore(async (store, directory) => {
    await writeFile(join(directory, "7.json"), JSON.stringify({
      version: 1,
      installationId: 8,
      accountLogin: "example",
      accountType: "Organization",
      repositorySelection: "selected",
      repositories: ["example/repo"],
      updatedAt: "2026-08-22T18:00:00.000Z",
    }));
    await assert.rejects(() => store.get(7), /does not match/);
  });
});

test("installation listing is deterministic", async () => {
  await withStore(async (store) => {
    await store.put({ installationId: 20, accountLogin: "b", accountType: "User", repositorySelection: "selected", repositories: [] });
    await store.put({ installationId: 3, accountLogin: "a", accountType: "User", repositorySelection: "selected", repositories: [] });
    assert.deepEqual((await store.list()).map((entry) => entry.installationId), [3, 20]);
  });
});
