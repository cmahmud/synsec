import assert from "node:assert/strict";
import test from "node:test";
import {
  isSynSecHostedInstallationFreshlyAuthorized,
  reverifySynSecHostedGitHubInstallation,
} from "@synsec/github/hosted-installation-reverification";

function principal(overrides = {}) {
  return { subject: "user_123", tenantId: "tenant-a", githubUserId: 101, ...overrides };
}

function installation(overrides = {}) {
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
    async getAccessibleInstallation() { return installation(); },
    ...overrides,
  };
}

function store(overrides = {}) {
  return {
    async beginReverification(tenantId, installationId, githubUserId) {
      return { epoch: 7, tenantId, installationId, githubUserId, accountId: 5001, accountType: "Organization" };
    },
    async finishVerified() { return "applied"; },
    async finishRevoked() { return "applied"; },
    async isFreshlyAuthorized() { return true; },
    ...overrides,
  };
}

test("hosted ownership reverification applies fresh user access with a durable fence", async () => {
  let finished;
  const result = await reverifySynSecHostedGitHubInstallation({
    principal: principal(),
    installationId: 9001,
    transport: transport(),
    store: store({ async finishVerified(input) { finished = input; return "applied"; } }),
  });
  assert.deepEqual(result, {
    status: "verified",
    tenantId: "tenant-a",
    installationId: 9001,
    epoch: 7,
    interpretation: "fresh-user-access-and-fenced-durable-reverification-only",
  });
  assert.equal(finished.accountLogin, "synsec-org");
  assert.doesNotMatch(JSON.stringify(result), /token|secret|authorization/i);
});

test("definitive inaccessible and suspended observations revoke but retain the durable tenant fence", async () => {
  const reasons = [];
  const backing = store({ async finishRevoked(input) { reasons.push(input.reason); return "applied"; } });
  const inaccessible = await reverifySynSecHostedGitHubInstallation({
    principal: principal(), installationId: 9001,
    transport: transport({ async getAccessibleInstallation() { return undefined; } }), store: backing,
  });
  const suspended = await reverifySynSecHostedGitHubInstallation({
    principal: principal(), installationId: 9001,
    transport: transport({ async getAccessibleInstallation() { return installation({ suspendedAt: "2026-08-25T00:00:00Z" }); } }), store: backing,
  });
  assert.equal(inaccessible.status, "revoked");
  assert.equal(inaccessible.reason, "inaccessible");
  assert.equal(suspended.reason, "suspended");
  assert.deepEqual(reasons, ["inaccessible", "suspended"]);
});

test("account identity drift revokes and a superseded result cannot overwrite a newer observation", async () => {
  const drift = await reverifySynSecHostedGitHubInstallation({
    principal: principal(), installationId: 9001,
    transport: transport({ async getAccessibleInstallation() { return installation({ account: { id: 9999, login: "other", type: "Organization" } }); } }),
    store: store(),
  });
  assert.equal(drift.status, "revoked");
  assert.equal(drift.reason, "account-identity-changed");

  const stale = await reverifySynSecHostedGitHubInstallation({
    principal: principal(), installationId: 9001, transport: transport(),
    store: store({ async finishVerified() { return "stale"; } }),
  });
  assert.equal(stale.status, "superseded");
});

test("transport failure does not manufacture revocation and diagnostics are sanitized", async () => {
  let revoked = false;
  await assert.rejects(
    reverifySynSecHostedGitHubInstallation({
      principal: principal(), installationId: 9001,
      transport: transport({ async getAccessibleInstallation() { throw new Error("Authorization: Bearer gh-secret"); } }),
      store: store({ async finishRevoked() { revoked = true; return "applied"; } }),
    }),
    (error) => error instanceof Error
      && error.message === "GitHub installation re-verification failed."
      && !error.message.includes("gh-secret"),
  );
  assert.equal(revoked, false);
});

test("reverification requires the durable proof user and freshness checks fail closed on backend errors", async () => {
  await assert.rejects(
    reverifySynSecHostedGitHubInstallation({
      principal: principal(), installationId: 9001, transport: transport(),
      store: store({ async beginReverification() { return undefined; } }),
    }),
    /proof does not match/,
  );
  assert.equal(await isSynSecHostedInstallationFreshlyAuthorized({
    tenantId: "tenant-a", installationId: 9001, maxAgeMs: 60_000, store: store(),
  }), true);
  await assert.rejects(
    isSynSecHostedInstallationFreshlyAuthorized({
      tenantId: "tenant-a", installationId: 9001, maxAgeMs: 60_000,
      store: store({ async isFreshlyAuthorized() { throw new Error("postgresql://secret@db/tenant"); } }),
    }),
    (error) => error instanceof Error
      && error.message === "Hosted installation authorization freshness check failed."
      && !error.message.includes("secret"),
  );
});
