import assert from "node:assert/strict";
import test from "node:test";
import { createSynSecGitHubAppIntakeHost } from "@synsec/github/app-intake-host";

const scenarioIds = [
  "replay.concurrent-duplicate-claim",
  "queue.concurrent-idempotent-insert",
  "queue.concurrent-claim-fence",
  "queue.stale-fence-renewal",
  "queue.stale-fence-terminal-transitions",
  "installation.concurrent-selection-mutation",
  "authorization.cross-replica-revocation",
];

function profile(overrides = {}) {
  return {
    releaseId: "v0.2.0-test",
    replicaId: "intake-a",
    replicaCount: 2,
    appId: 1234,
    credentialDirectory: "/run/secrets/synsec/github",
    postgresUrlEnvironment: "SYNSEC_POSTGRES_URL",
    listenHost: "127.0.0.1",
    port: 32123,
    tlsMode: "terminated-upstream",
    workspaceDirectory: "/var/lib/synsec/workspaces",
    scannerRuntimeCommand: "docker",
    scannerImage: `example.invalid/synsec-scanner@sha256:${"a".repeat(64)}`,
    operatorStatusPath: "/operator/status",
    ...overrides,
  };
}

function report() {
  return {
    schemaVersion: 1,
    backendId: "postgres-v1",
    implementationVersion: "0.2.0-postgres-v1",
    complete: true,
    scenarioTimeoutMs: 10_000,
    results: scenarioIds.map((id) => ({ id, status: "passed", durationMs: 1 })),
    coverage: {
      complete: true,
      coveredScenarioIds: [...scenarioIds],
      missingScenarioIds: [],
      missingCapabilities: [],
    },
  };
}

function snapshot(generation = "generation-1") {
  return {
    generation,
    privateKey: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
    webhookSecret: "s".repeat(32),
  };
}

function fakePool() {
  let connects = 0;
  const client = {
    async query(text) {
      if (text.includes("SELECT version FROM synsec_github_schema")) return { rows: [] };
      return { rows: [] };
    },
    release() {},
  };
  return {
    get connects() { return connects; },
    async connect() {
      connects += 1;
      return client;
    },
    async query() {
      return { rows: [] };
    },
  };
}

test("intake host rejects detached conformance evidence before credential or database access", async () => {
  const pool = fakePool();
  let credentialLoads = 0;
  await assert.rejects(
    createSynSecGitHubAppIntakeHost({
      profile: profile(),
      pool,
      conformanceReport: { schemaVersion: 1 },
      async loadCredentials() {
        credentialLoads += 1;
        return snapshot();
      },
    }),
    /shared-state evidence is not ready/,
  );
  assert.equal(credentialLoads, 0);
  assert.equal(pool.connects, 0);
});

test("intake host composes validated PostgreSQL intake with memory-only credential generations", async () => {
  const pool = fakePool();
  let generation = 1;
  const host = await createSynSecGitHubAppIntakeHost({
    profile: profile(),
    pool,
    conformanceReport: report(),
    async loadCredentials() {
      return snapshot(`generation-${generation++}`);
    },
  });

  assert.equal(pool.connects, 1);
  assert.equal(host.profile.replicaId, "intake-a");
  assert.equal(host.interpretation, "executable-intake-host-boundary-not-worker-or-fleet-readiness");
  assert.equal(host.drain.status().acceptingWebhooks, true);
  assert.deepEqual(host.credentialStatus(), {
    version: 1,
    generation: "generation-1",
    webhookSecretCount: 1,
    reloadCount: 0,
    interpretation: "memory-only-runtime-credential-generation",
  });

  const reloaded = await host.reloadCredentials();
  assert.equal(reloaded.generation, "generation-2");
  assert.equal(reloaded.reloadCount, 1);
  assert.equal(host.credentialStatus().generation, "generation-2");
});

test("intake host validates TLS ownership before loading credentials or migrating", async () => {
  const pool = fakePool();
  let credentialLoads = 0;
  await assert.rejects(
    createSynSecGitHubAppIntakeHost({
      profile: profile({ tlsMode: "local" }),
      pool,
      conformanceReport: report(),
      async loadCredentials() {
        credentialLoads += 1;
        return snapshot();
      },
    }),
    /local TLS requires caller-owned key and certificate material/,
  );
  assert.equal(credentialLoads, 0);
  assert.equal(pool.connects, 0);
});

test("intake host rejects caller TLS material when TLS terminates upstream", async () => {
  const pool = fakePool();
  let credentialLoads = 0;
  await assert.rejects(
    createSynSecGitHubAppIntakeHost({
      profile: profile(),
      pool,
      conformanceReport: report(),
      tls: { key: "key", cert: "cert" },
      async loadCredentials() {
        credentialLoads += 1;
        return snapshot();
      },
    }),
    /TLS material is accepted only for local TLS mode/,
  );
  assert.equal(credentialLoads, 0);
  assert.equal(pool.connects, 0);
});
