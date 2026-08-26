import assert from "node:assert/strict";
import test from "node:test";
import pg from "pg";
import { countSynSecGitHubPostgresActiveLeases } from "@synsec/github/postgres-lease-observer";
import { migrateSynSecGitHubPostgresBackend } from "@synsec/github/postgres-shared-backend";
import { PostgresGitHubScanQueue } from "@synsec/github/postgres-shared-state";

const connectionString = process.env.SYNSEC_TEST_POSTGRES_URL?.trim();
const integration = connectionString ? test : test.skip;

function job(deliveryId, byte) {
  return {
    deliveryId,
    installationId: 77,
    repository: "synsec/maintenance",
    headSha: byte.repeat(40),
    event: "push",
    createdAt: "2026-08-25T00:00:00.000Z",
  };
}

test("PostgreSQL durable lease observer rejects malformed backend result shapes", async () => {
  await assert.rejects(
    countSynSecGitHubPostgresActiveLeases({
      async query() { return { rows: [] }; },
      async connect() { throw new Error("unused"); },
    }),
    /invalid result shape/i,
  );
  await assert.rejects(
    countSynSecGitHubPostgresActiveLeases({
      async query() { return { rows: [{ count: -1 }] }; },
      async connect() { throw new Error("unused"); },
    }),
    /invalid count/i,
  );
});

integration("PostgreSQL durable lease observer counts only currently valid fenced leases", async () => {
  const pool = new pg.Pool({ connectionString, max: 8, application_name: "synsec-lease-observer-test" });
  try {
    await migrateSynSecGitHubPostgresBackend(pool);
    await pool.query("TRUNCATE synsec_github_scan_jobs, synsec_github_replay, synsec_github_installations");
    const queue = new PostgresGitHubScanQueue(pool, { leaseMs: 10_000 });

    await queue.enqueue(job("maintenance-lease-1", "a"));
    await queue.enqueue(job("maintenance-lease-2", "b"));
    const first = await queue.claimNext();
    const second = await queue.claimNext();
    assert.ok(first?.leaseId);
    assert.ok(second?.leaseId);
    assert.equal(await countSynSecGitHubPostgresActiveLeases(pool), 2);

    await pool.query(
      "UPDATE synsec_github_scan_jobs SET lease_until = clock_timestamp() - interval '1 second' WHERE job_id = $1",
      [first.jobId],
    );
    assert.equal(await countSynSecGitHubPostgresActiveLeases(pool), 1);

    assert.equal(await queue.complete(second.jobId, second.leaseId), true);
    assert.equal(await countSynSecGitHubPostgresActiveLeases(pool), 0);
  } finally {
    await pool.end();
  }
});
