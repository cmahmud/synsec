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
import { runGitHubAppSharedStateConformance } from "@synsec/github/shared-state-conformance-runner";

const connectionString = process.env.SYNSEC_TEST_POSTGRES_URL?.trim();
const integration = connectionString ? test : test.skip;

function pushJob(deliveryId = "delivery-1") {
  return {
    deliveryId,
    installationId: 9001,
    repository: "synsec/example",
    headSha: "a".repeat(40),
    event: "push",
    createdAt: "2026-08-24T00:00:00.000Z",
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

integration("PostgreSQL passes the canonical seven-scenario shared-state conformance matrix", async () => {
  const pool = new pg.Pool({ connectionString, max: 16 });
  try {
    await migrateSynSecGitHubPostgresState(pool);
    await migrateSynSecGitHubPostgresInstallationState(pool);

    const queueA = () => new PostgresGitHubScanQueue(pool, { leaseMs: 10_000 });
    const queueB = () => new PostgresGitHubScanQueue(pool, { leaseMs: 10_000 });
    const replayA = () => new PostgresGitHubWebhookReplayStore(pool);
    const replayB = () => new PostgresGitHubWebhookReplayStore(pool);
    const installationA = () => new PostgresGitHubInstallationStore(pool);
    const installationB = () => new PostgresGitHubInstallationStore(pool);

    const adapter = {
      backendId: "postgres-v1",
      implementationVersion: "0.2.0-postgres-v1",
      async reset() {
        await pool.query("TRUNCATE synsec_github_scan_jobs, synsec_github_replay, synsec_github_installations");
      },
      scenarios: {
        async "replay.concurrent-duplicate-claim"() {
          const claims = await Promise.all([
            replayA().claim("conformance-replay-1"),
            replayB().claim("conformance-replay-1"),
          ]);
          assert.equal(claims.filter((claim) => claim.accepted).length, 1);
          assert.equal(claims.filter((claim) => !claim.accepted).length, 1);
          assert.equal(claims[0].receivedAt, claims[1].receivedAt);
        },

        async "queue.concurrent-idempotent-insert"() {
          const first = queueA();
          const second = queueB();
          const results = await Promise.allSettled([
            first.enqueue(pushJob("conformance-insert-1")),
            second.enqueue(pushJob("conformance-insert-1")),
          ]);
          assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
          assert.equal((await first.list()).length, 1);
        },

        async "queue.concurrent-claim-fence"() {
          const first = queueA();
          const second = queueB();
          await first.enqueue(pushJob("conformance-claim-1"));
          const claims = await Promise.all([first.claimNext(), second.claimNext()]);
          assert.equal(claims.filter(Boolean).length, 1);
          const claimed = claims.find(Boolean);
          assert.ok(claimed?.leaseId);
          await first.assertLease(claimed.jobId, claimed.leaseId);
        },

        async "queue.stale-fence-renewal"() {
          const first = queueA();
          const second = queueB();
          await first.enqueue(pushJob("conformance-renew-1"));
          const oldLease = await first.claimNext();
          assert.ok(oldLease?.leaseId);
          await pool.query(
            "UPDATE synsec_github_scan_jobs SET lease_until = clock_timestamp() - interval '1 second' WHERE job_id = $1",
            [oldLease.jobId],
          );
          const newLease = await second.claimNext();
          assert.ok(newLease?.leaseId);
          assert.notEqual(newLease.leaseId, oldLease.leaseId);
          await assert.rejects(first.renew(oldLease.jobId, oldLease.leaseId));
          await second.assertLease(newLease.jobId, newLease.leaseId);
        },

        async "queue.stale-fence-terminal-transitions"() {
          const first = queueA();
          const second = queueB();
          await first.enqueue(pushJob("conformance-terminal-1"));
          const oldLease = await first.claimNext();
          assert.ok(oldLease?.leaseId);
          await pool.query(
            "UPDATE synsec_github_scan_jobs SET lease_until = clock_timestamp() - interval '1 second' WHERE job_id = $1",
            [oldLease.jobId],
          );
          const newLease = await second.claimNext();
          assert.ok(newLease?.leaseId);
          await assert.rejects(first.release(oldLease.jobId, oldLease.leaseId));
          await assert.rejects(first.fail(oldLease.jobId, oldLease.leaseId));
          await assert.rejects(first.complete(oldLease.jobId, oldLease.leaseId));
          await second.assertLease(newLease.jobId, newLease.leaseId);
        },

        async "installation.concurrent-selection-mutation"() {
          const first = installationA();
          const second = installationB();
          await synchronizeGitHubInstallationState(
            installationEvent(),
            first,
            Date.parse("2026-08-24T00:00:00.000Z"),
          );
          await Promise.all([
            synchronizeGitHubInstallationState(
              repositoryDelta("synsec/alpha"),
              first,
              Date.parse("2026-08-24T00:00:01.000Z"),
            ),
            synchronizeGitHubInstallationState(
              repositoryDelta("synsec/beta"),
              second,
              Date.parse("2026-08-24T00:00:02.000Z"),
            ),
          ]);
          assert.deepEqual((await first.get(9001))?.repositories, [
            "synsec/alpha",
            "synsec/base",
            "synsec/beta",
          ]);
        },

        async "authorization.cross-replica-revocation"() {
          const first = installationA();
          const second = installationB();
          await synchronizeGitHubInstallationState(
            installationEvent(),
            first,
            Date.parse("2026-08-24T00:00:00.000Z"),
          );
          assert.equal(await second.isRepositoryAllowed(9001, "synsec/base"), true);
          await synchronizeGitHubInstallationState(
            installationEvent({
              action: "suspend",
              suspendedAt: "2026-08-24T00:00:03.000Z",
              repositories: [],
            }),
            first,
            Date.parse("2026-08-24T00:00:03.000Z"),
          );
          assert.equal(await second.isRepositoryAllowed(9001, "synsec/base"), false);
        },
      },
    };

    const report = await runGitHubAppSharedStateConformance(adapter, { scenarioTimeoutMs: 10_000 });
    assert.equal(report.backendId, "postgres-v1");
    assert.equal(report.implementationVersion, "0.2.0-postgres-v1");
    assert.equal(report.complete, true);
    assert.deepEqual(report.coverage.missingCapabilities, []);
    assert.deepEqual(report.results.map(({ id, status }) => [id, status]), [
      ["replay.concurrent-duplicate-claim", "passed"],
      ["queue.concurrent-idempotent-insert", "passed"],
      ["queue.concurrent-claim-fence", "passed"],
      ["queue.stale-fence-renewal", "passed"],
      ["queue.stale-fence-terminal-transitions", "passed"],
      ["installation.concurrent-selection-mutation", "passed"],
      ["authorization.cross-replica-revocation", "passed"],
    ]);
  } finally {
    await pool.end();
  }
});
