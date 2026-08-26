import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createLocalGitHubAppRuntime } from "@synsec/github/app-runtime";

function privateKeyPem() {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return privateKey.export({ type: "pkcs8", format: "pem" });
}

async function runtimeOptions(replicaCount) {
  const root = await mkdtemp(join(tmpdir(), "synsec-local-replica-"));
  return {
    stateDirectory: join(root, "state"),
    workspaceRoot: join(root, "workspaces"),
    webhookSecret: "runtime-webhook-secret",
    appId: 12345,
    privateKey: privateKeyPem(),
    config: { scanners: ["opengrep"], parallelism: 1 },
    ...(replicaCount !== undefined ? { replicaCount } : {}),
  };
}

test("local filesystem runtime accepts omitted or explicit single-replica cardinality", async () => {
  for (const replicaCount of [undefined, 1]) {
    const runtime = await createLocalGitHubAppRuntime(await runtimeOptions(replicaCount));
    assert.deepEqual(await runtime.runWorkerOnce(), { status: "idle" });
  }
});

test("local filesystem runtime rejects horizontal replica declarations before creating state", async () => {
  for (const replicaCount of [0, 2, 10, 1.5, Number.NaN]) {
    const options = await runtimeOptions(replicaCount);
    await assert.rejects(
      () => createLocalGitHubAppRuntime(options),
      /supports exactly one application replica/,
      String(replicaCount),
    );
  }
});
