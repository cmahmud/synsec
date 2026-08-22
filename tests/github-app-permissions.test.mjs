import assert from "node:assert/strict";
import test from "node:test";

import {
  diagnoseGitHubAppWorkerPermissions,
  requiredGitHubAppWorkerPermissions,
} from "@synsec/github/app-permissions";

test("worker permission diagnostics report the minimum non-SARIF requirements", () => {
  assert.deepEqual(requiredGitHubAppWorkerPermissions(), [
    { permission: "contents", level: "read", purpose: "repository-acquisition" },
    { permission: "checks", level: "write", purpose: "check-publication" },
  ]);

  const result = diagnoseGitHubAppWorkerPermissions({ contents: "read", checks: "write" });
  assert.equal(result.ok, true);
  assert.equal(result.metadataAvailable, true);
  assert.equal(result.diagnostics.every((item) => item.status === "satisfied"), true);
});

test("worker permission diagnostics add security_events only when SARIF publication is enabled", () => {
  const required = requiredGitHubAppWorkerPermissions({ publishSarif: true });
  assert.deepEqual(required.map((item) => `${item.permission}:${item.level}`), [
    "contents:read",
    "checks:write",
    "security_events:write",
  ]);

  const result = diagnoseGitHubAppWorkerPermissions({
    contents: "write",
    checks: "write",
    security_events: "write",
  }, { publishSarif: true });
  assert.equal(result.ok, true);
});

test("worker permission diagnostics distinguish missing and insufficient permissions", () => {
  const result = diagnoseGitHubAppWorkerPermissions({ contents: "read", checks: "read" }, { publishSarif: true });
  assert.equal(result.ok, false);
  assert.equal(result.diagnostics.find((item) => item.permission === "contents").status, "satisfied");
  assert.equal(result.diagnostics.find((item) => item.permission === "checks").status, "insufficient");
  assert.equal(result.diagnostics.find((item) => item.permission === "security_events").status, "missing");
  assert.match(result.diagnostics.find((item) => item.permission === "checks").message, /checks:read is insufficient/);
});

test("missing GitHub permission metadata fails closed as unknown", () => {
  const result = diagnoseGitHubAppWorkerPermissions(undefined, { publishSarif: true });
  assert.equal(result.ok, false);
  assert.equal(result.metadataAvailable, false);
  assert.equal(result.diagnostics.every((item) => item.status === "unknown"), true);
});
