import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { access, mkdir, mkdtemp, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createLocalGitHubAppRuntime } from "@synsec/github/app-runtime";
import { markGitHubWorkspaceOwned } from "@synsec/github/workspace-ownership";

function privateKeyPem() {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return privateKey.export({ type: "pkcs8", format: "pem" });
}

async function textFiles(root) {
  const result = [];
  async function walk(path) {
    for (const entry of await readdir(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) await walk(child);
      else if (entry.isFile()) result.push(await readFile(child, "utf8"));
    }
  }
  await walk(root);
  return result;
}

test("local App runtime composes durable stores, maintenance, status, and an idle worker without persisting credentials", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-app-runtime-"));
  const stateDirectory = join(root, "state");
  const workspaceRoot = join(root, "workspaces");
  const privateKey = privateKeyPem();
  const webhookSecret = "runtime-webhook-secret";
  const runtime = await createLocalGitHubAppRuntime({
    stateDirectory,
    workspaceRoot,
    webhookSecret,
    appId: 12345,
    privateKey,
    config: { scanners: ["opengrep"], parallelism: 1 },
  });

  assert.equal(runtime.stateDirectory, stateDirectory);
  assert.equal(runtime.workspaceRoot, workspaceRoot);
  assert.equal(typeof runtime.webhookHandler, "function");
  assert.deepEqual(await runtime.runWorkerOnce(), { status: "idle" });
  assert.deepEqual(await runtime.runMaintenance(), {
    expiredReplayRecordsDeleted: 0,
    failedJobs: { inspected: 0, deleted: 0, retainedFailed: 0 },
    workspaces: { inspected: 0, owned: 0, stale: 0, deleted: 0, skipped: 0 },
  });
  assert.deepEqual(await runtime.getStatus(), {
    installations: { total: 0, active: 0, suspended: 0, allRepositories: 0, selectedRepositories: 0 },
    queue: { total: 0, pending: 0, leased: 0, failed: 0 },
  });

  const persisted = (await textFiles(stateDirectory)).join("\n");
  assert.equal(persisted.includes(webhookSecret), false);
  assert.equal(persisted.includes(privateKey.slice(0, 32)), false);
});

test("runtime workspace cleanup is opt-in and removes only stale marker-owned directories", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-app-runtime-workspaces-"));
  const stateDirectory = join(root, "state");
  const workspaceRoot = join(root, "workspaces");
  await mkdir(workspaceRoot, { recursive: true });
  const now = Date.parse("2026-08-22T20:00:00.000Z");
  const stale = join(workspaceRoot, "synsec-github-stale");
  const unrelated = join(workspaceRoot, "synsec-github-unowned");
  await mkdir(stale);
  await mkdir(unrelated);
  await markGitHubWorkspaceOwned(stale, () => now - 2 * 60 * 60 * 1000);

  const observe = await createLocalGitHubAppRuntime({
    stateDirectory,
    workspaceRoot,
    webhookSecret: "runtime-webhook-secret",
    appId: 12345,
    privateKey: privateKeyPem(),
    config: { scanners: ["opengrep"], parallelism: 1 },
    workspaceRetentionMs: 60 * 60 * 1000,
    now: () => now,
  });
  assert.deepEqual((await observe.runMaintenance()).workspaces, {
    inspected: 2,
    owned: 1,
    stale: 1,
    deleted: 0,
    skipped: 1,
  });
  await access(stale);

  const cleanup = await createLocalGitHubAppRuntime({
    stateDirectory,
    workspaceRoot,
    webhookSecret: "runtime-webhook-secret",
    appId: 12345,
    privateKey: privateKeyPem(),
    config: { scanners: ["opengrep"], parallelism: 1 },
    workspaceRetentionMs: 60 * 60 * 1000,
    deleteStaleOwnedWorkspaces: true,
    now: () => now,
  });
  assert.equal((await cleanup.runMaintenance()).workspaces.deleted, 1);
  await assert.rejects(() => access(stale), /ENOENT/);
  await access(unrelated);
});

test("local App runtime refuses overlapping durable state and scanner workspace trees", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-app-runtime-overlap-"));
  const base = {
    webhookSecret: "secret",
    appId: 12345,
    privateKey: privateKeyPem(),
    config: { scanners: ["opengrep"], parallelism: 1 },
  };

  await assert.rejects(() => createLocalGitHubAppRuntime({
    ...base,
    stateDirectory: join(root, "state"),
    workspaceRoot: join(root, "state", "workspaces"),
  }), /separate directory trees/);
  await assert.rejects(() => createLocalGitHubAppRuntime({
    ...base,
    stateDirectory: join(root, "workspaces", "state"),
    workspaceRoot: join(root, "workspaces"),
  }), /separate directory trees/);
});
