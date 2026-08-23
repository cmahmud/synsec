import assert from "node:assert/strict";
import test from "node:test";
import { execFile } from "node:child_process";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const exec = promisify(execFile);
const cli = new URL("../apps/cli/dist/github-app-cli.js", import.meta.url);

async function runExpectingExit(args, expectedCode) {
  try {
    await exec(process.execPath, [cli.pathname, ...args]);
    assert.fail(`Expected exit code ${expectedCode}.`);
  } catch (error) {
    assert.equal(error.code, expectedCode);
    return error;
  }
}

test("rotation CLI fails closed while webhook verification remains incomplete", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-app-rotation-"));
  try {
    const path = join(root, "rotation.json");
    await writeFile(path, JSON.stringify({
      kind: "webhook-secret",
      replacementActivated: true,
      runtimeReloaded: true,
      externalConfigurationUpdated: true,
    }), "utf8");
    const error = await runExpectingExit(["rotation", path, "--json"], 2);
    const output = JSON.parse(error.stdout);
    assert.equal(output.readyToRetirePrevious, false);
    assert.match(output.requiredActions.join("\n"), /authenticated GitHub webhook delivery/);
    assert.match(output.requiredActions.at(-1), /Keep the previous webhook secret/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rotation CLI returns ready only after private-key token exchange verification", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-app-rotation-ready-"));
  try {
    const path = join(root, "rotation.json");
    await writeFile(path, JSON.stringify({
      kind: "app-private-key",
      replacementActivated: true,
      runtimeReloaded: true,
      verificationSucceeded: true,
    }), "utf8");
    const { stdout } = await exec(process.execPath, [cli.pathname, "rotation", path, "--json"]);
    const output = JSON.parse(stdout);
    assert.equal(output.readyToRetirePrevious, true);
    assert.deepEqual(output.requiredActions, []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rotation CLI rejects credential-bearing fields without echoing their values", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-app-rotation-secret-"));
  try {
    const path = join(root, "rotation.json");
    await writeFile(path, JSON.stringify({
      kind: "webhook-secret",
      replacementActivated: true,
      secret: "do-not-echo-this-secret-value",
    }), "utf8");
    const error = await runExpectingExit(["rotation", path], 1);
    assert.match(error.stderr, /unsupported field secret/);
    assert.doesNotMatch(error.stderr, /do-not-echo-this-secret-value/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("GitHub App diagnostic inputs reject symlinks without reading their target", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-app-rotation-symlink-"));
  try {
    const target = join(root, "target.json");
    const link = join(root, "rotation.json");
    await writeFile(target, JSON.stringify({
      kind: "webhook-secret",
      secret: "target-secret-must-not-be-read",
    }), "utf8");
    await symlink(target, link);

    const error = await runExpectingExit(["rotation", link], 1);
    assert.match(error.stderr, /non-symlink regular file/);
    assert.doesNotMatch(error.stderr, /target-secret-must-not-be-read/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
