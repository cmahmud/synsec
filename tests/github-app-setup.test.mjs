import assert from "node:assert/strict";
import test from "node:test";
import {
  buildSynSecGitHubAppSetupContract,
  buildSynSecGitHubAppSetupRecoveryPlan,
  evaluateSynSecGitHubAppSetup,
} from "@synsec/github/app-setup";

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

test("setup evaluator distinguishes missing capability from least-privilege drift", () => {
  const evaluation = evaluateSynSecGitHubAppSetup({
    permissions: {
      contents: "write",
      checks: "read",
      issues: "write",
    },
    events: ["push", "pull_request", "issues"],
  });

  assert.equal(evaluation.ready, false);
  assert.deepEqual(evaluation.missingPermissions, [{
    permission: "checks",
    required: "write",
    actual: "read",
  }]);
  assert.deepEqual(evaluation.excessiveWritePermissions, ["contents", "issues"]);
  assert.deepEqual(evaluation.missingEvents, ["installation", "installation_repositories"]);
  assert.deepEqual(evaluation.extraEvents, ["issues"]);
  assert.equal(evaluation.interpretation, "setup-comparison-not-runtime-authorization");
});

test("setup evaluator accepts exactly the feature-aware minimum", () => {
  const setup = buildSynSecGitHubAppSetupContract({ publishSarif: true, enableRemediationPullRequests: true });
  const evaluation = evaluateSynSecGitHubAppSetup({
    permissions: setup.permissions,
    events: setup.events,
    options: { publishSarif: true, enableRemediationPullRequests: true },
  });
  assert.deepEqual(evaluation, {
    version: 1,
    ready: true,
    missingPermissions: [],
    excessiveWritePermissions: [],
    missingEvents: [],
    extraEvents: [],
    interpretation: "setup-comparison-not-runtime-authorization",
  });
});

test("setup recovery plan separates required fixes from least-privilege review", () => {
  const plan = buildSynSecGitHubAppSetupRecoveryPlan({
    permissions: {
      contents: "write",
      checks: "read",
      issues: "write",
    },
    events: ["push", "pull_request", "issues"],
  });

  assert.deepEqual(plan, {
    version: 1,
    ready: false,
    requiredActions: [
      "Upgrade GitHub App permission checks from read to write.",
      "Subscribe the GitHub App to the installation event.",
      "Subscribe the GitHub App to the installation_repositories event.",
    ],
    leastPrivilegeReview: [
      "Review contents:write and remove it if no other operator-approved feature requires it.",
      "Review issues:write and remove it if no other operator-approved feature requires it.",
      "Review the issues event subscription and remove it if no other operator-approved feature requires it.",
    ],
    interpretation: "operator-guidance-not-runtime-authorization",
  });
});

test("setup recovery plan is empty when the feature-aware minimum is satisfied", () => {
  const setup = buildSynSecGitHubAppSetupContract({ publishSarif: true });
  const plan = buildSynSecGitHubAppSetupRecoveryPlan({
    permissions: setup.permissions,
    events: setup.events,
    options: { publishSarif: true },
  });
  assert.equal(plan.ready, true);
  assert.deepEqual(plan.requiredActions, []);
  assert.deepEqual(plan.leastPrivilegeReview, []);
});

test("setup evaluator validates bounded permission and event names before comparison", () => {
  assert.throws(() => evaluateSynSecGitHubAppSetup({
    permissions: { "contents\nwrite": "write" },
    events: ["push"],
  }), /invalid permission name/);
  assert.throws(() => evaluateSynSecGitHubAppSetup({
    permissions: { contents: "read" },
    events: ["pull request"],
  }), /invalid event name/);

  const tooManyPermissions = Object.fromEntries(
    Array.from({ length: 101 }, (_, index) => [`permission_${index}`, "read"]),
  );
  assert.throws(() => evaluateSynSecGitHubAppSetup({
    permissions: tooManyPermissions,
    events: ["push"],
  }), /permission list exceeds 100 entries/);
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
