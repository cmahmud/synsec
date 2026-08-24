import assert from "node:assert/strict";
import test from "node:test";
import pg from "pg";
import {
  migrateSynSecGitHubPostgresState,
  PostgresGitHubScanQueue,
  PostgresGitHubWebhookReplayStore,
} from "@synsec/github/postgres-shared-state";
import {
  migrateSynSecGitHubPostgresInstallationState,
  PostgresGitHubInstallationStore,
} from "@synsec/github/postgres-installation-store";
import { synchronizeGitHubInstallationState } from "@synsec/github/installation-sync";

const connectionString = process.env.SYNSEC_TEST_POSTGRES_URL?.trim();
const integration = connectionString ? test : test.skip;

function job(deliveryId, headByte, createdAt) {
  return {
    deliveryId,
    installationId: 42,
    repository: "synsec/example",
    headSha: headByte.repeat(40),
    event: "push",
    createdAt,
  };
}

function installationEvent(overrides = {}) {
  return {
    event: "installation",
    action: "created",
    installationId: 4242,
    accountLogin: "synsec-org",
    accountType: "Organization",
    repositorySelection: "selected",
    repositories: ["synsec/base"],
    repositoriesAdded: [],
    repositoriesRemoved: [],
    ...overrides,
  };
}

function repositoryDelta(repository) {
  return installationEvent({
    event: "installation_repositories",
    action: "added",
    repositories: [],
    repositoriesAdded: [repository],
  });
}

integration("PostgreSQL migrations are idempotent and record the exact shared-state schema version", async () => {
  const pool = new pg.Pool({ connectionString, max: 4 });
  try {
    await migrateSynSecGitHubPostgresState(pool);
    await migrateSynSecGitHubPostgresState(pool);
    await migrateSynSecGitHubPostgresInstallationState(pool);
    await migrateSynSecGitHubPostgresInstallationState(pool);
    const result = await pool.query("SELECT version FROM synsec_github_schema WHERE component = 'shared-state'");
    assert.deepEqual(result.rows, [{ version: 1 }]);
  } finally {
    await pool.end();
  }
});

integration("PostgreSQL replay claims are atomic across independent store instances", async () => {
  const pool = new pg.Pool({ connectionString, max: 8 });
  try {
    await migrateSynSecGitHubPostgresState(pool);
    await pool.query("DELETE FROM synsec_github_replay");
    const first = new PostgresGitHubWebhookReplayStore(pool);
    const second = new PostgresGitHubWebhookReplayStore(pool);
    const claims = await Promise.all([
      first.claim("delivery-concurrent-1"),
      second.claim("delivery-concurrent-1"),
    ]);
    assert.equal(claims.filter((claim) => claim.accepted).length, 1);
    assert.equal(claims.filter((claim) => !claim.accepted).length, 1);
    assert.equal(claims[0].receivedAt, claims[1].receivedAt);

    const accepted = claims.find((claim) => claim.accepted);
    assert.ok(accepted);
    assert.equal(await second.release(accepted.deliveryId, "2026-01-01T00:00:00.000Z"), false);
    assert.equal(await first.release(accepted.deliveryId, accepted.receivedAt), true);
    assert.equal((await second.claim(accepted.deliveryId)).accepted, true);
  } finally {
    await pool.end();
  }
});

integration("PostgreSQL queue enforces unique insertion and competing fenced claims", async () => {
  const pool = new pg.Pool({ connectionString, max: 12 });
  try {
    await migrateSynSecGitHubPostgresState(pool);
    await pool.query("DELETE FROM synsec_github_scan_jobs");
    const queueA = new PostgresGitHubScanQueue(pool, { leaseMs: 10_000 });
    const queueB = new PostgresGitHubScanQueue(pool, { leaseMs: 10_000 });

    const duplicate = job("queue-duplicate-1", "a", "2026-08-24T00:00:00.000Z");
    const inserts = await Promise.allSettled([queueA.enqueue(duplicate), queueB.enqueue(duplicate)]);
    assert.equal(inserts.filter((result) => result.status === "fulfilled").length, 1);
    assert.equal(inserts.filter((result) => result.status === "rejected").length, 1);
    await pool.query("DELETE FROM synsec_github_scan_jobs");

    await queueA.enqueue(job("queue-claim-1", "b", "2026-08-24T00:00:01.000Z"));
    await queueA.enqueue(job("queue-claim-2", "c", "2026-08-24T00:00:02.000Z"));
    const [claimedA, claimedB] = await Promise.all([queueA.claimNext(), queueB.claimNext()]);
    assert.ok(claimedA?.leaseId);
    assert.ok(claimedB?.leaseId);
    assert.notEqual(claimedA.jobId, claimedB.jobId);
    assert.notEqual(claimedA.leaseId, claimedB.leaseId);
    assert.equal(claimedA.attempts, 1);
    assert.equal(claimedB.attempts, 1);
  } finally {
    await pool.end();
  }
});

integration("PostgreSQL queue rejects a stale fence after lease reclamation", async () => {
  const pool = new pg.Pool({ connectionString, max: 8 });
  try {
    await migrateSynSecGitHubPostgresState(pool);
    await pool.query("DELETE FROM synsec_github_scan_jobs");
    const queueA = new PostgresGitHubScanQueue(pool, { leaseMs: 10_000 });
    const queueB = new PostgresGitHubScanQueue(pool, { leaseMs: 10_000 });
    await queueA.enqueue(job("queue-fence-1", "d", "2026-08-24T00:00:03.000Z"));
    const oldLease = await queueA.claimNext();
    assert.ok(oldLease?.leaseId);

    await pool.query(
      "UPDATE synsec_github_scan_jobs SET lease_until = clock_timestamp() - interval '1 second' WHERE job_id = $1",
      [oldLease.jobId],
    );
    const newLease = await queueB.claimNext();
    assert.equal(newLease?.jobId, oldLease.jobId);
    assert.ok(newLease?.leaseId);
    assert.notEqual(newLease.leaseId, oldLease.leaseId);
    assert.equal(newLease.attempts, 2);

    await assert.rejects(
      queueA.renew(oldLease.jobId, oldLease.leaseId),
      /stale, expired, or no longer owned/,
    );
    assert.equal(await queueB.complete(newLease.jobId, newLease.leaseId), true);
    assert.deepEqual(await queueA.list(), []);
  } finally {
    await pool.end();
  }
});

integration("PostgreSQL installation deltas are serialized transactionally across independent stores", async () => {
  const pool = new pg.Pool({ connectionString, max: 12 });
  try {
    await migrateSynSecGitHubPostgresInstallationState(pool);
    await pool.query("DELETE FROM synsec_github_installations");
    const storeA = new PostgresGitHubInstallationStore(pool);
    const storeB = new PostgresGitHubInstallationStore(pool);
    await synchronizeGitHubInstallationState(installationEvent(), storeA, Date.parse("2026-08-24T00:00:00.000Z"));

    await Promise.all([
      synchronizeGitHubInstallationState(repositoryDelta("synsec/alpha"), storeA, Date.parse("2026-08-24T00:00:01.000Z")),
      synchronizeGitHubInstallationState(repositoryDelta("synsec/beta"), storeB, Date.parse("2026-08-24T00:00:02.000Z")),
    ]);

    const record = await storeA.get(4242);
    assert.deepEqual(record?.repositories, ["synsec/alpha", "synsec/base", "synsec/beta"]);
  } finally {
    await pool.end();
  }
});

integration("PostgreSQL authorization revocation is immediately shared across store instances", async () => {
  const pool = new pg.Pool({ connectionString, max: 8 });
  try {
    await migrateSynSecGitHubPostgresInstallationState(pool);
    await pool.query("DELETE FROM synsec_github_installations");
    const storeA = new PostgresGitHubInstallationStore(pool);
    const storeB = new PostgresGitHubInstallationStore(pool);
    await synchronizeGitHubInstallationState(installationEvent(), storeA, Date.parse("2026-08-24T00:00:00.000Z"));
    assert.equal(await storeB.isRepositoryAllowed(4242, "synsec/base"), true);
    assert.equal(await storeB.isRepositoryAllowed(4242, "synsec/other"), false);

    await synchronizeGitHubInstallationState(
      installationEvent({ action: "suspend", suspendedAt: "2026-08-24T00:00:03.000Z", repositories: [] }),
      storeA,
      Date.parse("2026-08-24T00:00:03.000Z"),
    );
    assert.equal(await storeB.isRepositoryAllowed(4242, "synsec/base"), false);

    await synchronizeGitHubInstallationState(
      installationEvent({ action: "unsuspend", repositories: [] }),
      storeB,
      Date.parse("2026-08-24T00:00:04.000Z"),
    );
    assert.equal(await storeA.isRepositoryAllowed(4242, "synsec/base"), true);

    await synchronizeGitHubInstallationState(
      installationEvent({ action: "deleted", accountLogin: undefined, accountType: undefined, repositorySelection: undefined, repositories: [] }),
      storeA,
      Date.parse("2026-08-24T00:00:05.000Z"),
    );
    assert.equal(await storeB.isRepositoryAllowed(4242, "synsec/base"), false);
  } finally {
    await pool.end();
  }
});
