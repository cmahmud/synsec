import assert from "node:assert/strict";
import test from "node:test";
import { buildSynSecGitHubAppSetupContract } from "@synsec/github/app-setup";

test("default GitHub App setup remains read-only for repository contents", () => {
  const setup = buildSynSecGitHubAppSetupContract();
  assert.equal(setup.version, 1);
  assert.deepEqual(setup.permissions, {
    contents: "read",
    checks: "write",
  });
  assert.equal(setup.remediationWriteEnabled, false);
  assert.deepEqual(setup.events, [
    "installation",
    "installation_repositories",
    "pull_request",
    "push",
  ]);
  assert.match(setup.notes.join("\n"), /contents:read is sufficient/);
});

test("SARIF adds only security-events publication permission", () => {
  const setup = buildSynSecGitHubAppSetupContract({ publishSarif: true });
  assert.deepEqual(setup.permissions, {
    contents: "read",
    checks: "write",
    security_events: "write",
  });
  assert.equal(setup.permissions.pull_requests, undefined);
});

test("remediation write permissions are explicit opt-in and contents write subsumes acquisition read", () => {
  const setup = buildSynSecGitHubAppSetupContract({
    publishSarif: true,
    enableRemediationPullRequests: true,
  });
  assert.deepEqual(setup.permissions, {
    contents: "write",
    checks: "write",
    security_events: "write",
    pull_requests: "write",
  });
  assert.equal(setup.remediationWriteEnabled, true);
  assert.match(setup.notes.join("\n"), /explicitly approved remediation PR creation/);
});

test("setup contract contains no installation, repository-target, credential, or commit identity", () => {
  const setup = buildSynSecGitHubAppSetupContract({ enableRemediationPullRequests: true });
  const serialized = JSON.stringify(setup);
  for (const forbidden of [
    "installationId",
    "accountLogin",
    "example/private-repository",
    "installation-token-value",
    "a".repeat(40),
    "clone_url",
    "targetUrl",
  ]) {
    assert.equal(serialized.includes(forbidden), false);
  }
  assert.deepEqual(Object.keys(setup).sort(), [
    "events",
    "notes",
    "permissions",
    "remediationWriteEnabled",
    "version",
  ]);
});
