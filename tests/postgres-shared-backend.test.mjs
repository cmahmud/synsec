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
import { synchronizeGitHubInstallationState } from "@synsec/github/installation-sync";
import { assessGitHubAppSharedStateBackendContract } from "@synsec/github/shared-state-contract";

const connectionString = process.env.SYNSEC_TEST_POSTGRES_URL?.trim();
const integration = connectionString ? test : test.skip;

function pushJob(deliveryId) {
  return {
    deliveryId,
    installationId: 9001,
    repository: "synsec/example",
    headSha: "b".repeat(40),
    event: "push",
    createdAt: "2026-08-24T12:00:00.000Z",
  };
}

function installationEvent(overrides = {}) {
  return {
    event: "installation",
    action: "created",
    installationId: 9001,
    accountLogin: "synsec-org",
    accountType: "Organization",
    repositorySelection: "selected",
    repositories: ["synsec/example"],
    repositoriesAdded: [],
    repositoriesRemoved: [],
    ...overrides,
  };
}

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

integration("PostgreSQL replay, queue fencing, and authorization survive pool teardown and reconnect", async () => {
  let firstPool = new pg.Pool({ connectionString, max: 4, application_name: "synsec-restart-before" });
  let secondPool;
  try {
    await migrateSynSecGitHubPostgresBackend(firstPool);
    await firstPool.query("TRUNCATE synsec_github_scan_jobs, synsec_github_replay, synsec_github_installations");

    const before = createSynSecGitHubPostgresSharedStores(firstPool, { leaseMs: 10_000 });
    const replayClaim = await before.replayStore.claim("restart-replay-1");
    assert.equal(replayClaim.accepted, true);

    await synchronizeGitHubInstallationState(
      installationEvent(),
      before.installationStore,
      Date.parse("2026-08-24T12:00:00.000Z"),
    );
    assert.equal(await before.installationStore.isRepositoryAllowed(9001, "synsec/example"), true);

    await before.queue.enqueue(pushJob("restart-job-1"));
    const leasedBeforeRestart = await before.queue.claimNext();
    assert.ok(leasedBeforeRestart?.leaseId);

    await firstPool.end();
    firstPool = undefined;

    secondPool = new pg.Pool({ connectionString, max: 4, application_name: "synsec-restart-after" });
    const after = createSynSecGitHubPostgresSharedStores(secondPool, { leaseMs: 10_000 });

    const duplicate = await after.replayStore.claim("restart-replay-1");
    assert.equal(duplicate.accepted, false);
    assert.equal(duplicate.receivedAt, replayClaim.receivedAt);

    assert.equal(await after.installationStore.isRepositoryAllowed(9001, "synsec/example"), true);
    await synchronizeGitHubInstallationState(
      installationEvent({ action: "suspend", suspendedAt: "2026-08-24T12:00:01.000Z", repositories: [] }),
      after.installationStore,
      Date.parse("2026-08-24T12:00:01.000Z"),
    );
    assert.equal(await after.installationStore.isRepositoryAllowed(9001, "synsec/example"), false);

    const durableLease = await after.queue.assertLease(leasedBeforeRestart.jobId, leasedBeforeRestart.leaseId);
    assert.equal(durableLease.jobId, leasedBeforeRestart.jobId);
    const renewed = await after.queue.renew(leasedBeforeRestart.jobId, leasedBeforeRestart.leaseId);
    assert.equal(renewed.leaseId, leasedBeforeRestart.leaseId);
    assert.equal(await after.queue.complete(leasedBeforeRestart.jobId, leasedBeforeRestart.leaseId), true);
    assert.deepEqual(await after.queue.list(), []);
  } finally {
    if (firstPool) await firstPool.end();
    if (secondPool) await secondPool.end();
  }
});
