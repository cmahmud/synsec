import assert from "node:assert/strict";
import test from "node:test";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
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

test("GitHub App setup CLI prints the feature-aware minimum as JSON", async () => {
  const { stdout } = await exec(process.execPath, [
    cli.pathname,
    "requirements",
    "--sarif",
    "--remediation",
    "--json",
  ]);
  const output = JSON.parse(stdout);
  assert.deepEqual(output.permissions, {
    contents: "write",
    checks: "write",
    security_events: "write",
    pull_requests: "write",
  });
  assert.equal(output.remediationWriteEnabled, true);
  assert.deepEqual(output.events, [
    "installation",
    "installation_repositories",
    "pull_request",
    "push",
  ]);
});

test("GitHub App setup CLI evaluates a least-privilege configuration offline", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-app-setup-"));
  try {
    const setupPath = join(root, "setup.json");
    await writeFile(setupPath, JSON.stringify({
      permissions: {
        contents: "read",
        checks: "write",
      },
      events: ["installation", "installation_repositories", "pull_request", "push"],
    }), "utf8");

    const { stdout } = await exec(process.execPath, [cli.pathname, "evaluate", setupPath, "--json"]);
    const output = JSON.parse(stdout);
    assert.equal(output.ready, true);
    assert.deepEqual(output.missingPermissions, []);
    assert.deepEqual(output.missingEvents, []);
    assert.deepEqual(output.excessiveWritePermissions, []);
    assert.equal(output.interpretation, "setup-comparison-not-runtime-authorization");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("GitHub App setup CLI exits 2 when required capability is missing", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-app-setup-missing-"));
  try {
    const setupPath = join(root, "setup.json");
    await writeFile(setupPath, JSON.stringify({
      permissions: { contents: "read" },
      events: ["push"],
    }), "utf8");

    const error = await runExpectingExit(["evaluate", setupPath, "--json"], 2);
    const output = JSON.parse(error.stdout);
    assert.equal(output.ready, false);
    assert.ok(output.missingPermissions.some((item) => item.permission === "checks"));
    assert.ok(output.missingEvents.includes("pull_request"));
    assert.ok(output.missingEvents.includes("installation"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("GitHub App setup CLI can enforce least-privilege drift in strict mode", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-app-setup-strict-"));
  try {
    const setupPath = join(root, "setup.json");
    await writeFile(setupPath, JSON.stringify({
      permissions: {
        contents: "write",
        checks: "write",
        issues: "write",
      },
      events: ["installation", "installation_repositories", "pull_request", "push", "issues"],
    }), "utf8");

    const error = await runExpectingExit(["evaluate", setupPath, "--json", "--strict"], 3);
    const output = JSON.parse(error.stdout);
    assert.equal(output.ready, true);
    assert.deepEqual(output.excessiveWritePermissions, ["contents", "issues"]);
    assert.deepEqual(output.extraEvents, ["issues"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("GitHub App setup CLI rejects credential-shaped or malformed setup documents by schema", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-app-setup-invalid-"));
  try {
    const setupPath = join(root, "setup.json");
    await writeFile(setupPath, JSON.stringify({
      permissions: { contents: "admin" },
      events: ["push"],
      privateKey: "must-not-be-used",
    }), "utf8");

    const error = await runExpectingExit(["evaluate", setupPath], 1);
    assert.match(error.stderr, /permission contents must be read or write/);
    assert.doesNotMatch(error.stderr, /must-not-be-used/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
