import assert from "node:assert/strict";
import test from "node:test";
import { execFile } from "node:child_process";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const exec = promisify(execFile);
const cli = new URL("../apps/cli/dist/github-app-credential-reload-cli.js", import.meta.url);

async function runExpectingExit(args, expectedCode) {
  try {
    await exec(process.execPath, [cli.pathname, ...args]);
    assert.fail(`Expected exit code ${expectedCode}.`);
  } catch (error) {
    assert.equal(error.code, expectedCode);
    return error;
  }
}

test("credential reload CLI reports complete deployment state", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-credential-reload-"));
  try {
    const path = join(root, "reload.json");
    await writeFile(path, JSON.stringify({
      kind: "webhook-secret",
      targetGeneration: "webhook-v3",
      expectedReplicaCount: 2,
      replicas: [
        { replicaId: "synsec-0", loadedGeneration: "webhook-v3", ready: true },
        { replicaId: "synsec-1", loadedGeneration: "webhook-v3", ready: true },
      ],
    }), "utf8");

    const { stdout } = await exec(process.execPath, [cli.pathname, path, "--json"]);
    const output = JSON.parse(stdout);
    assert.equal(output.complete, true);
    assert.equal(output.matchedReplicaCount, 2);
    assert.equal(output.missingReplicaCount, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("credential reload CLI exits 2 for stale replica state", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-credential-reload-stale-"));
  try {
    const path = join(root, "reload.json");
    await writeFile(path, JSON.stringify({
      kind: "app-private-key",
      targetGeneration: "key-v4",
      expectedReplicaCount: 2,
      replicas: [
        { replicaId: "synsec-0", loadedGeneration: "key-v4", ready: true },
        { replicaId: "synsec-1", loadedGeneration: "key-v3", ready: true },
      ],
    }), "utf8");

    const error = await runExpectingExit([path, "--json"], 2);
    const output = JSON.parse(error.stdout);
    assert.equal(output.complete, false);
    assert.equal(output.staleReplicaCount, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("credential reload CLI rejects credential-bearing fields without echoing values", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-credential-reload-secret-"));
  try {
    const path = join(root, "reload.json");
    await writeFile(path, JSON.stringify({
      kind: "webhook-secret",
      targetGeneration: "webhook-v3",
      expectedReplicaCount: 1,
      replicas: [],
      secret: "do-not-echo-reload-secret",
    }), "utf8");

    const error = await runExpectingExit([path], 1);
    assert.match(error.stderr, /unsupported field secret/);
    assert.doesNotMatch(error.stderr, /do-not-echo-reload-secret/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("credential reload CLI rejects symlink inputs without reading targets", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-credential-reload-link-"));
  try {
    const target = join(root, "target.json");
    const link = join(root, "reload.json");
    await writeFile(target, JSON.stringify({ secret: "target-secret-must-not-leak" }), "utf8");
    await symlink(target, link);

    const error = await runExpectingExit([link], 1);
    assert.match(error.stderr, /non-symlink regular file/);
    assert.doesNotMatch(error.stderr, /target-secret-must-not-leak/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("credential reload CLI rejects unsupported options without reflecting their values", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-credential-reload-option-"));
  try {
    const path = join(root, "reload.json");
    await writeFile(path, JSON.stringify({
      kind: "webhook-secret",
      targetGeneration: "webhook-v3",
      expectedReplicaCount: 1,
      replicas: [{ replicaId: "synsec-0", loadedGeneration: "webhook-v3", ready: true }],
    }), "utf8");

    const error = await runExpectingExit([path, "--token=do-not-reflect-this"], 1);
    assert.match(error.stderr, /Unsupported credential reload CLI option/);
    assert.doesNotMatch(error.stderr, /do-not-reflect-this/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
