import assert from "node:assert/strict";
import test from "node:test";
import pg from "pg";
import {
  buildSynSecGitHubPostgresBackendContract,
  createGitHubAppPostgresSharedRuntime,
  createSynSecGitHubPostgresSharedStores,
  migrateSynSecGitHubPostgresBackend,
  SYNSEC_GITHUB_POSTGRES_BACKEND_ID,
  SYNSEC_GITHUB_POSTGRES_IMPLEMENTATION_VERSION,
} from "@synsec/github/postgres-shared-backend";
import { assessGitHubAppSharedStateBackendContract } from "@synsec/github/shared-state-contract";

const connectionString = process.env.SYNSEC_TEST_POSTGRES_URL?.trim();
const integration = connectionString ? test : test.skip;

test("built-in PostgreSQL backend contract declares every required capability without connection details", () => {
  const contract = buildSynSecGitHubPostgresBackendContract();
  const assessment = assessGitHubAppSharedStateBackendContract(contract);
  assert.equal(assessment.ready, true);
  assert.deepEqual(assessment.missingEvidence, []);
  assert.equal(contract.backendId, SYNSEC_GITHUB_POSTGRES_BACKEND_ID);
  assert.equal(contract.implementationVersion, SYNSEC_GITHUB_POSTGRES_IMPLEMENTATION_VERSION);
  const serialized = JSON.stringify(contract);
  assert.doesNotMatch(serialized, /postgresql:\/\//i);
  assert.doesNotMatch(serialized, /password|connectionString|databaseUrl/i);
});

test("PostgreSQL runtime composition still fails closed without matching conformance evidence", () => {
  const pool = {
    async query() { throw new Error("database should not be queried during composition"); },
    async connect() { throw new Error("database should not be connected during composition"); },
  };
  assert.throws(
    () => createGitHubAppPostgresSharedRuntime({
      pool,
      conformanceReport: {},
      webhookSecret: "0123456789abcdef0123456789abcdef",
      worker: {},
    }),
    /conformance evidence is not ready/,
  );
});

integration("composed PostgreSQL migration serializes concurrent deployment invocations", async () => {
  const pool = new pg.Pool({ connectionString, max: 8 });
  try {
    await Promise.all([
      migrateSynSecGitHubPostgresBackend(pool),
      migrateSynSecGitHubPostgresBackend(pool),
      migrateSynSecGitHubPostgresBackend(pool),
      migrateSynSecGitHubPostgresBackend(pool),
    ]);
    const schema = await pool.query(
      "SELECT version FROM synsec_github_schema WHERE component = 'shared-state'",
    );
    assert.deepEqual(schema.rows, [{ version: 1 }]);
    const stores = createSynSecGitHubPostgresSharedStores(pool, { leaseMs: 10_000 });
    assert.equal(stores.queue.leaseMs, 10_000);
    assert.equal(typeof stores.replayStore.claim, "function");
    assert.equal(typeof stores.installationStore.isRepositoryAllowed, "function");
  } finally {
    await pool.end();
  }
});
