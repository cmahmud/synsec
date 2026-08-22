import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createLocalGitHubAppRuntime } from "@synsec/github/app-runtime";

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

test("local App runtime composes durable stores, maintenance, and an idle worker without persisting credentials", async () => {
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
  });

  const persisted = (await textFiles(stateDirectory)).join("\n");
  assert.equal(persisted.includes(webhookSecret), false);
  assert.equal(persisted.includes(privateKey.slice(0, 32)), false);
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
