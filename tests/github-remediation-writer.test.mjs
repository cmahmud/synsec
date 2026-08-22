import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createApprovedGitHubRemediationPullRequest } from "@synsec/github/remediation-writer";
import {
  approveRemediationProposal,
  authorizeRemediationExecution,
  createRemediationProposal,
} from "@synsec/workflows/remediation";
import { getWorkflow } from "@synsec/workflows";

const target = "a".repeat(40);
const commit = "b".repeat(40);
const token = "installation-token-that-must-not-appear-in-argv";

function execution() {
  const proposal = createRemediationProposal(getWorkflow("repository-review"), {
    targetCommitSha: target,
    findingIds: ["finding-1", "finding-2"],
    summary: "Apply the reviewed repository-local hardening patch.",
    changes: [
      {
        path: "src/handler.ts",
        operation: "modify",
        patch: "diff --git a/src/handler.ts b/src/handler.ts\n--- a/src/handler.ts\n+++ b/src/handler.ts\n@@ -1 +1 @@\n-old\n+new\n",
      },
      {
        path: "tests/handler.test.ts",
        operation: "create",
        patch: "diff --git a/tests/handler.test.ts b/tests/handler.test.ts\nnew file mode 100644\n--- /dev/null\n+++ b/tests/handler.test.ts\n@@ -0,0 +1 @@\n+test('guard', () => {});\n",
      },
    ],
  });
  const approval = approveRemediationProposal(proposal, {
    proposalId: proposal.proposalId,
    approvedBy: "security-reviewer",
    approvedAt: "2026-08-22T20:30:00.000Z",
  });
  return authorizeRemediationExecution({ proposal, approval, currentHeadSha: target });
}

function gitHarness({ baseSha = target, staged = "M\tsrc/handler.ts\nA\ttests/handler.test.ts\n", existingBranchSha } = {}) {
  const calls = [];
  const runner = async (args, options) => {
    calls.push({ args: [...args], options });
    assert.equal(args.some((value) => value.includes(token)), false);
    if (args[0] === "rev-parse") {
      const remediationCommitCreated = calls.some((call) => call.args[0] === "commit");
      return { exitCode: 0, stdout: `${remediationCommitCreated ? commit : target}\n`, stderr: "" };
    }
    if (args[0] === "ls-remote") {
      const ref = args.at(-1);
      if (ref === "refs/heads/main") return { exitCode: 0, stdout: `${baseSha}\t${ref}\n`, stderr: "" };
      if (existingBranchSha) return { exitCode: 0, stdout: `${existingBranchSha}\t${ref}\n`, stderr: "" };
      return { exitCode: 2, stdout: "", stderr: "" };
    }
    if (args[0] === "diff") return { exitCode: 0, stdout: staged, stderr: "" };
    return { exitCode: 0, stdout: "", stderr: "" };
  };
  return { calls, runner };
}

function fetchHarness() {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return new Response(JSON.stringify({
      number: 17,
      html_url: "https://github.com/example/repo/pull/17",
    }), { status: 201, headers: { "content-type": "application/json" } });
  };
  return { calls, fetchImpl };
}

test("GitHub remediation writer rechecks provenance, applies only approved paths, pushes non-force, and opens a PR", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "synsec-remediation-writer-"));
  const git = gitHarness();
  const http = fetchHarness();
  const result = await createApprovedGitHubRemediationPullRequest({
    repository: "example/repo",
    baseBranch: "main",
    workspace,
    installationToken: token,
    execution: execution(),
  }, { gitRunner: git.runner, fetch: http.fetchImpl });

  assert.equal(result.repository, "example/repo");
  assert.equal(result.commitSha, commit);
  assert.equal(result.pullRequestNumber, 17);
  assert.match(result.branch, /^synsec\/remediation\/[a-f0-9]{20}$/);

  const commands = git.calls.map((call) => call.args);
  assert.deepEqual(commands.slice(0, 2).map((args) => args[0]), ["rev-parse", "ls-remote"]);
  assert.ok(commands.some((args) => args[0] === "apply" && args.includes("--check")));
  assert.ok(commands.some((args) => args[0] === "diff" && args.includes("--no-renames")));
  const push = commands.find((args) => args[0] === "push");
  assert.ok(push);
  assert.equal(push.includes("--force"), false);
  assert.equal(push[1], "https://github.com/example/repo.git");

  assert.equal(http.calls.length, 1);
  assert.equal(http.calls[0].url, "https://api.github.com/repos/example/repo/pulls");
  assert.equal(http.calls[0].init.redirect, "error");
  assert.equal(http.calls[0].init.headers.authorization, `Bearer ${token}`);
  const body = JSON.parse(http.calls[0].init.body);
  assert.equal(body.base, "main");
  assert.equal(body.head, result.branch);
  assert.match(body.body, /explicit approval/);
});

test("GitHub remediation writer refuses a moved base before applying patches", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "synsec-remediation-stale-"));
  const git = gitHarness({ baseSha: "c".repeat(40) });
  const http = fetchHarness();
  await assert.rejects(() => createApprovedGitHubRemediationPullRequest({
    repository: "example/repo",
    baseBranch: "main",
    workspace,
    installationToken: token,
    execution: execution(),
  }, { gitRunner: git.runner, fetch: http.fetchImpl }), /base branch moved/);
  assert.equal(git.calls.some((call) => call.args[0] === "apply"), false);
  assert.equal(http.calls.length, 0);
});

test("GitHub remediation writer rejects staged scope expansion before commit or push", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "synsec-remediation-scope-"));
  const git = gitHarness({ staged: "M\tsrc/handler.ts\nA\ttests/handler.test.ts\nA\tunexpected.txt\n" });
  const http = fetchHarness();
  await assert.rejects(() => createApprovedGitHubRemediationPullRequest({
    repository: "example/repo",
    baseBranch: "main",
    workspace,
    installationToken: token,
    execution: execution(),
  }, { gitRunner: git.runner, fetch: http.fetchImpl }), /staged paths differ/);
  assert.equal(git.calls.some((call) => call.args[0] === "commit"), false);
  assert.equal(git.calls.some((call) => call.args[0] === "push"), false);
  assert.equal(http.calls.length, 0);
});

test("GitHub remediation writer treats the deterministic branch as idempotent only when commit contents match", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "synsec-remediation-idempotent-"));
  const same = gitHarness({ existingBranchSha: commit });
  const http = fetchHarness();
  await createApprovedGitHubRemediationPullRequest({
    repository: "example/repo",
    baseBranch: "main",
    workspace,
    installationToken: token,
    execution: execution(),
  }, { gitRunner: same.runner, fetch: http.fetchImpl });
  assert.equal(same.calls.some((call) => call.args[0] === "push"), false);
  assert.equal(http.calls.length, 1);

  const conflicting = gitHarness({ existingBranchSha: "d".repeat(40) });
  await assert.rejects(() => createApprovedGitHubRemediationPullRequest({
    repository: "example/repo",
    baseBranch: "main",
    workspace,
    installationToken: token,
    execution: execution(),
  }, { gitRunner: conflicting.runner, fetch: http.fetchImpl }), /already exists with different contents/);
});
