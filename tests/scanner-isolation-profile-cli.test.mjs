import assert from "node:assert/strict";
import test from "node:test";
import { execFile } from "node:child_process";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const exec = promisify(execFile);
const cli = new URL("../apps/cli/dist/scanner-isolation-profile-cli.js", import.meta.url);

async function runExpectingExit(args, expectedCode) {
  try {
    await exec(process.execPath, [cli.pathname, ...args]);
    assert.fail(`Expected exit code ${expectedCode}.`);
  } catch (error) {
    assert.equal(error.code, expectedCode);
    return error;
  }
}

const completeProfile = {
  schemaVersion: 1,
  runtime: "container",
  cpuLimit: true,
  memoryLimit: true,
  networkPolicy: "none",
  repositoryReadOnly: true,
  rootFilesystemReadOnly: true,
  scratchSeparated: true,
  credentialsExcluded: true,
  durableStateExcluded: true,
  privileged: false,
  allowPrivilegeEscalation: false,
  runAsNonRoot: true,
  capabilitiesDropped: true,
  hostNetwork: false,
  hostPid: false,
  hostIpc: false,
  hostSocketMounts: false,
};

test("scanner isolation CLI accepts a complete secret-free profile", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-isolation-ready-"));
  try {
    const path = join(root, "profile.json");
    await writeFile(path, JSON.stringify(completeProfile), "utf8");
    const { stdout } = await exec(process.execPath, [cli.pathname, path, "--json"]);
    assert.deepEqual(JSON.parse(stdout), {
      complete: true,
      missing: [],
      interpretation: "declared-infrastructure-controls-not-runtime-certification",
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("scanner isolation CLI exits 2 with deterministic missing controls", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-isolation-missing-"));
  try {
    const path = join(root, "profile.json");
    await writeFile(path, JSON.stringify({
      ...completeProfile,
      memoryLimit: false,
      networkPolicy: "none",
      repositoryReadOnly: false,
      rootFilesystemReadOnly: false,
      allowPrivilegeEscalation: true,
      runAsNonRoot: false,
      hostSocketMounts: true,
    }), "utf8");
    const error = await runExpectingExit([path, "--json"], 2);
    assert.deepEqual(JSON.parse(error.stdout).missing, [
      "memory-limit",
      "read-only-repository",
      "read-only-root-filesystem",
      "no-privilege-escalation",
      "run-as-non-root",
      "no-host-socket-mounts",
    ]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("scanner isolation CLI rejects unknown fields without echoing field names or values", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-isolation-secret-"));
  try {
    const path = join(root, "profile.json");
    const secretKey = "ghp_must_not_echo_in_key_1234567890";
    const secretValue = "ghp_must_not_echo_in_value_1234567890";
    await writeFile(path, JSON.stringify({
      ...completeProfile,
      [secretKey]: secretValue,
    }), "utf8");
    const error = await runExpectingExit([path], 1);
    assert.match(error.stderr, /contains an unsupported field/);
    assert.doesNotMatch(error.stderr, /ghp_must_not_echo/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("scanner isolation CLI rejects symlink profile inputs", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-isolation-symlink-"));
  try {
    const target = join(root, "target.json");
    const link = join(root, "profile.json");
    await writeFile(target, JSON.stringify(completeProfile), "utf8");
    await symlink(target, link);
    const error = await runExpectingExit([link], 1);
    assert.match(error.stderr, /non-symlink regular file/);
    assert.doesNotMatch(error.stderr, /target\.json/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("scanner isolation CLI rejects unsupported options without reflecting their values", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-isolation-option-"));
  try {
    const path = join(root, "profile.json");
    await writeFile(path, JSON.stringify(completeProfile), "utf8");
    const error = await runExpectingExit([path, "--token=must-not-echo"], 1);
    assert.match(error.stderr, /Unsupported scanner isolation verifier option/);
    assert.doesNotMatch(error.stderr, /must-not-echo/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
