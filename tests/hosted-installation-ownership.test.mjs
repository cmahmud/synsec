import assert from "node:assert/strict";
import test from "node:test";
import { verifyAndClaimSynSecHostedGitHubInstallation } from "@synsec/github/hosted-installation-ownership";

function principal(overrides = {}) {
  return {
    subject: "user_123",
    tenantId: "tenant-a",
    githubUserId: 101,
    ...overrides,
  };
}

function accessible(overrides = {}) {
  return {
    id: 9001,
    account: { id: 5001, login: "synsec-org", type: "Organization" },
    repositorySelection: "selected",
    ...overrides,
  };
}

function transport(overrides = {}) {
  return {
    async getAuthenticatedUser() { return { id: 101, login: "maintainer" }; },
    async getAccessibleInstallation() { return accessible(); },
    ...overrides,
  };
}

test("hosted installation ownership verifies the bound GitHub user and returns secret-free structural evidence", async () => {
  let claimed;
  const result = await verifyAndClaimSynSecHostedGitHubInstallation({
    principal: principal(),
    installationId: 9001,
    transport: transport(),
    store: {
      async claim(input) {
        claimed = input;
        return "claimed";
      },
    },
  });
  assert.equal(result.status, "verified");
  assert.equal(result.tenantId, "tenant-a");
  assert.equal(result.installationId, 9001);
  assert.equal(result.ownership, "claimed");
  assert.equal(result.interpretation, "authenticated-user-access-and-atomic-tenant-claim-only");
  assert.deepEqual(claimed, {
    tenantId: "tenant-a",
    installationId: 9001,
    githubUserId: 101,
    accountId: 5001,
    accountLogin: "synsec-org",
    accountType: "Organization",
  });
  assert.doesNotMatch(JSON.stringify(result), /token|secret|authorization/i);
});

test("hosted installation ownership rejects a GitHub identity that does not match the authenticated session", async () => {
  await assert.rejects(
    verifyAndClaimSynSecHostedGitHubInstallation({
      principal: principal(),
      installationId: 9001,
      transport: transport({ async getAuthenticatedUser() { return { id: 202, login: "other" }; } }),
      store: { async claim() { throw new Error("must not claim"); } },
    }),
    /does not match the hosted session/,
  );
});

test("hosted installation ownership fails closed when the user cannot access the installation or it is suspended", async () => {
  await assert.rejects(
    verifyAndClaimSynSecHostedGitHubInstallation({
      principal: principal(),
      installationId: 9001,
      transport: transport({ async getAccessibleInstallation() { return undefined; } }),
      store: { async claim() { return "claimed"; } },
    }),
    /not accessible/,
  );
  await assert.rejects(
    verifyAndClaimSynSecHostedGitHubInstallation({
      principal: principal(),
      installationId: 9001,
      transport: transport({ async getAccessibleInstallation() { return accessible({ suspendedAt: "2026-08-25T00:00:00Z" }); } }),
      store: { async claim() { return "claimed"; } },
    }),
    /Suspended GitHub installations cannot be claimed/,
  );
});

test("hosted installation ownership rejects cross-tenant claims and sanitizes transport/persistence failures", async () => {
  await assert.rejects(
    verifyAndClaimSynSecHostedGitHubInstallation({
      principal: principal(),
      installationId: 9001,
      transport: transport(),
      store: { async claim() { return "conflict"; } },
    }),
    /already claimed by another hosted tenant/,
  );

  await assert.rejects(
    verifyAndClaimSynSecHostedGitHubInstallation({
      principal: principal(),
      installationId: 9001,
      transport: transport({ async getAccessibleInstallation() { throw new Error("Authorization: Bearer gh-secret"); } }),
      store: { async claim() { return "claimed"; } },
    }),
    (error) => error instanceof Error
      && error.message === "GitHub installation ownership verification failed."
      && !error.message.includes("gh-secret"),
  );

  await assert.rejects(
    verifyAndClaimSynSecHostedGitHubInstallation({
      principal: principal(),
      installationId: 9001,
      transport: transport(),
      store: { async claim() { throw new Error("postgresql://user:password@db/tenant"); } },
    }),
    (error) => error instanceof Error
      && error.message === "Hosted installation ownership persistence failed."
      && !error.message.includes("password"),
  );
});
