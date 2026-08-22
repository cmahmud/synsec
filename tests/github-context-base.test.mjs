import test from "node:test";
import assert from "node:assert/strict";

import { detectGitHubContext } from "../packages/github/dist/index.js";

test("pull-request event context retains both head and base commit SHAs", () => {
  const context = detectGitHubContext(
    {
      GITHUB_REPOSITORY: "cmahmud/synsec",
      GITHUB_SHA: "synthetic-merge-sha",
      GITHUB_REF: "refs/pull/42/merge",
    },
    {
      repository: { full_name: "cmahmud/synsec" },
      pull_request: {
        number: 42,
        head: { sha: "head-commit", ref: "feature/security" },
        base: { sha: "base-commit", ref: "main" },
      },
    },
  );

  assert.equal(context.sha, "head-commit");
  assert.equal(context.baseSha, "base-commit");
  assert.equal(context.baseRef, "main");
  assert.equal(context.headRef, "feature/security");
});
