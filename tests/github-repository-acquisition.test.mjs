import assert from "node:assert/strict";
import { access, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  acquireGitHubRepositoryCommit,
  validateGitHubCommitSha,
  validateGitHubRepositoryIdentity,
} from "@synsec/github/repository-acquisition";

const sha = "0123456789abcdef0123456789abcdef01234567";

test("repository acquisition validates fixed-host owner/name identities", () => {
  assert.equal(validateGitHubRepositoryIdentity("cmahmud/synsec"), "cmahmud/synsec");
  assert.throws(() => validateGitHubRepositoryIdentity("github.com@attacker.invalid/repo"), /unsafe/);
  assert.throws(() => validateGitHubRepositoryIdentity("owner/repo/extra"), /owner\/name/);
  assert.throws(() => validateGitHubRepositoryIdentity("owner/../repo"), /owner\/name/);
  assert.equal(validateGitHubCommitSha(sha.toUpperCase()), sha);
  assert.throws(() => validateGitHubCommitSha("main"), /commit SHA/);
});

test("exact-commit acquisition keeps the installation token out of git argv and verifies HEAD", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-acquire-test-"));
  const calls = [];
  const token = "ghs_test-installation-token";
  const gitRunner = async (args, options) => {
    calls.push({ args: [...args], options });
    if (args[0] === "rev-parse") return { exitCode: 0, stdout: `${sha}\n`, stderr: "" };
    return { exitCode: 0, stdout: "", stderr: "" };
  };

  const acquired = await acquireGitHubRepositoryCommit({
    repository: "cmahmud/synsec",
    commitSha: sha,
    installationToken: token,
  }, { workspaceRoot: root, gitRunner, timeoutMs: 10_000 });

  assert.equal(acquired.repository, "cmahmud/synsec");
  assert.equal(acquired.commitSha, sha);
  assert.equal(calls.length, 4);
  assert.deepEqual(calls[1].args, [
    "fetch",
    "--quiet",
    "--no-tags",
    "--depth=1",
    "https://github.com/cmahmud/synsec.git",
    sha,
  ]);
  assert.equal(calls.some((call) => call.args.some((arg) => arg.includes(token))), false);
  assert.equal(calls[0].options.env.GIT_TERMINAL_PROMPT, "0");
  assert.equal(calls[0].options.env.GIT_CONFIG_NOSYSTEM, "1");
  assert.equal(calls[0].options.env.GIT_CONFIG_KEY_0, "http.https://github.com/.extraheader");
  assert.match(calls[0].options.env.GIT_CONFIG_VALUE_0, /^AUTHORIZATION: basic /);
  assert.equal(calls[0].options.env.GITHUB_TOKEN, undefined);
  assert.equal(calls[0].options.env.HTTPS_PROXY, undefined);
  assert.equal(calls[0].options.env.GIT_LFS_SKIP_SMUDGE, "1");

  await acquired.cleanup();
  await assert.rejects(() => access(acquired.workspace), /ENOENT/);
});

test("acquisition rejects malformed transport identity before invoking git", async () => {
  let called = false;
  await assert.rejects(() => acquireGitHubRepositoryCommit({
    repository: "github.com@attacker.invalid/repo",
    commitSha: sha,
    installationToken: "token",
  }, {
    gitRunner: async () => {
      called = true;
      return { exitCode: 0, stdout: "", stderr: "" };
    },
  }), /unsafe/);
  assert.equal(called, false);
});

test("acquisition removes the temporary workspace when commit provenance mismatches", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-acquire-mismatch-"));
  let workspace;
  const otherSha = "abcdef0123456789abcdef0123456789abcdef01";
  const gitRunner = async (args, options) => {
    workspace = options.cwd;
    if (args[0] === "rev-parse") return { exitCode: 0, stdout: `${otherSha}\n`, stderr: "" };
    return { exitCode: 0, stdout: "", stderr: "" };
  };

  await assert.rejects(() => acquireGitHubRepositoryCommit({
    repository: "cmahmud/synsec",
    commitSha: sha,
    installationToken: "token",
  }, { workspaceRoot: root, gitRunner, timeoutMs: 10_000 }), /different from the requested SHA/);

  assert.ok(workspace);
  await assert.rejects(() => access(workspace), /ENOENT/);
});
