import assert from "node:assert/strict";
import test from "node:test";
import { defaultConfig } from "@synsec/config";
import { builtInScanners, withBuiltInScannerFactory } from "@synsec/scanners";
import {
  assertGitHubAppOciWorkerConfig,
  createSynSecGitHubAppWorkerHost,
} from "@synsec/github/app-worker-host";

function scanner(id) {
  return {
    id,
    displayName: id,
    async checkAvailability() { return { available: true }; },
    async scan() { throw new Error("test scanner should not execute"); },
  };
}

function isolatedConfig(overrides = {}) {
  return {
    ...structuredClone(defaultConfig),
    scanners: ["grype", "syft"],
    ai: { ...defaultConfig.ai, enabled: false },
    ...overrides,
  };
}

function hostProfile() {
  return {
    releaseId: "0.2.0-test",
    replicaId: "worker-1",
    replicaCount: 2,
    appId: 12345,
    credentialDirectory: "/run/secrets/synsec-github",
    postgresUrlEnvironment: "SYNSEC_DATABASE_URL",
    listenHost: "127.0.0.1",
    port: 8443,
    tlsMode: "terminated-upstream",
    workspaceDirectory: "/var/lib/synsec/workspaces",
    scannerRuntimeCommand: "docker",
    scannerImage: `registry.example/synsec-scanners@sha256:${"a".repeat(64)}`,
    operatorStatusPath: "/_synsec/operator",
  };
}

test("scoped scanner factories remain isolated across concurrent async operations", async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });

  const first = withBuiltInScannerFactory(() => [scanner("isolated-a")], async () => {
    await gate;
    return builtInScanners().map((value) => value.id);
  });
  const second = withBuiltInScannerFactory(() => [scanner("isolated-b")], async () => {
    release();
    await Promise.resolve();
    return builtInScanners().map((value) => value.id);
  });

  assert.deepEqual(await first, ["isolated-a"]);
  assert.deepEqual(await second, ["isolated-b"]);
  assert.ok(builtInScanners().some((value) => value.id === "opengrep"));
});

test("scoped scanner factories reject empty and duplicate adapter sets", async () => {
  await assert.rejects(
    withBuiltInScannerFactory(() => [], async () => builtInScanners()),
    /at least one scanner adapter/,
  );
  await assert.rejects(
    withBuiltInScannerFactory(() => [scanner("same"), scanner("same")], async () => builtInScanners()),
    /duplicate scanner ids/,
  );
});

test("hosted OCI worker accepts only the currently enforced scanner subset", () => {
  assert.doesNotThrow(() => assertGitHubAppOciWorkerConfig(isolatedConfig()));
  assert.throws(
    () => assertGitHubAppOciWorkerConfig(isolatedConfig({ scanners: ["grype", "opengrep"] })),
    /without enforced hosted isolation support/,
  );
  assert.throws(
    () => assertGitHubAppOciWorkerConfig(isolatedConfig({ scanners: ["grype", "grype"] })),
    /duplicate scanner ids/,
  );
  assert.throws(
    () => assertGitHubAppOciWorkerConfig(isolatedConfig({ ai: { ...defaultConfig.ai, enabled: true } })),
    /does not enable AI review/,
  );
});

test("worker host rejects missing PostgreSQL conformance before credentials or database access", async () => {
  let credentialLoads = 0;
  let databaseCalls = 0;
  const pool = {
    async query() { databaseCalls += 1; throw new Error("database must not be reached"); },
    async connect() { databaseCalls += 1; throw new Error("database must not be reached"); },
  };

  await assert.rejects(
    createSynSecGitHubAppWorkerHost({
      profile: hostProfile(),
      pool,
      conformanceReport: {},
      config: isolatedConfig(),
      async loadCredentials() {
        credentialLoads += 1;
        throw new Error("credentials must not be reached");
      },
    }),
    /shared-state evidence is not ready/,
  );
  assert.equal(credentialLoads, 0);
  assert.equal(databaseCalls, 0);
});

test("worker host rejects unsupported scanners before credentials or database access", async () => {
  let credentialLoads = 0;
  let databaseCalls = 0;
  const pool = {
    async query() { databaseCalls += 1; throw new Error("database must not be reached"); },
    async connect() { databaseCalls += 1; throw new Error("database must not be reached"); },
  };

  await assert.rejects(
    createSynSecGitHubAppWorkerHost({
      profile: hostProfile(),
      pool,
      conformanceReport: {},
      config: isolatedConfig({ scanners: ["trivy"] }),
      async loadCredentials() {
        credentialLoads += 1;
        throw new Error("credentials must not be reached");
      },
    }),
    /without enforced hosted isolation support/,
  );
  assert.equal(credentialLoads, 0);
  assert.equal(databaseCalls, 0);
});
