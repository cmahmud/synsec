import assert from "node:assert/strict";
import test from "node:test";
import pg from "pg";
import {
  migrateSynSecGitHubPostgresHostedInstallationOwnership,
  PostgresSynSecHostedInstallationOwnershipStore,
} from "@synsec/github/postgres-hosted-installation-ownership";

const connectionString = process.env.SYNSEC_TEST_POSTGRES_URL?.trim();
const integration = connectionString ? test : test.skip;

function claim(tenantId = "tenant-a", overrides = {}) {
  return {
    tenantId,
    installationId: 9001,
    githubUserId: 101,
    accountId: 5001,
    accountLogin: "synsec-org",
    accountType: "Organization",
    ...overrides,
  };
}

integration("PostgreSQL hosted installation ownership atomically fences competing tenant claims across pools", async () => {
  const admin = new pg.Pool({ connectionString, max: 4, application_name: "synsec-hosted-owner-admin" });
  const replicaA = new pg.Pool({ connectionString, max: 4, application_name: "synsec-hosted-owner-a" });
  const replicaB = new pg.Pool({ connectionString, max: 4, application_name: "synsec-hosted-owner-b" });
  try {
    await migrateSynSecGitHubPostgresHostedInstallationOwnership(admin);
    await admin.query("TRUNCATE synsec_github_hosted_installation_ownership");
    const first = new PostgresSynSecHostedInstallationOwnershipStore(replicaA);
    const second = new PostgresSynSecHostedInstallationOwnershipStore(replicaB);

    const results = await Promise.all([
      first.claim(claim("tenant-a")),
      second.claim(claim("tenant-b", { githubUserId: 202 })),
    ]);
    assert.equal(results.filter((value) => value === "claimed").length, 1);
    assert.equal(results.filter((value) => value === "conflict").length, 1);

    const row = await admin.query(
      "SELECT installation_id, tenant_id, account_id, account_type FROM synsec_github_hosted_installation_ownership WHERE installation_id = 9001",
    );
    assert.equal(row.rows.length, 1);
    const durableTenant = row.rows[0].tenant_id;
    assert.ok(durableTenant === "tenant-a" || durableTenant === "tenant-b");

    const ownerStore = durableTenant === "tenant-a" ? first : second;
    const ownerUser = durableTenant === "tenant-a" ? 303 : 404;
    assert.equal(await ownerStore.claim(claim(durableTenant, { githubUserId: ownerUser, accountLogin: "renamed-org" })), "already-owned-by-tenant");

    const otherStore = durableTenant === "tenant-a" ? second : first;
    const otherTenant = durableTenant === "tenant-a" ? "tenant-b" : "tenant-a";
    assert.equal(await otherStore.release(otherTenant, 9001), false);
    assert.equal((await admin.query("SELECT count(*)::integer AS count FROM synsec_github_hosted_installation_ownership")).rows[0].count, 1);
    assert.equal(await ownerStore.release(durableTenant, 9001), true);
    assert.equal((await admin.query("SELECT count(*)::integer AS count FROM synsec_github_hosted_installation_ownership")).rows[0].count, 0);
  } finally {
    await Promise.allSettled([admin.end(), replicaA.end(), replicaB.end()]);
  }
});

integration("PostgreSQL hosted ownership refuses same-tenant account identity drift", async () => {
  const pool = new pg.Pool({ connectionString, max: 4 });
  try {
    await migrateSynSecGitHubPostgresHostedInstallationOwnership(pool);
    await pool.query("TRUNCATE synsec_github_hosted_installation_ownership");
    const store = new PostgresSynSecHostedInstallationOwnershipStore(pool);
    assert.equal(await store.claim(claim()), "claimed");
    assert.equal(await store.claim(claim("tenant-a", { accountId: 9999 })), "conflict");
    assert.equal(await store.claim(claim("tenant-a", { accountType: "User" })), "conflict");
  } finally {
    await pool.end();
  }
});
