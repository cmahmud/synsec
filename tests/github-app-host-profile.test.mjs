import assert from "node:assert/strict";
import test from "node:test";
import { parseGitHubAppHostProfile } from "@synsec/github/app-host-profile";

function profile(overrides = {}) {
  return {
    releaseId: "synsec-v0.2.0+e634364",
    replicaId: "github-app-01",
    replicaCount: 3,
    appId: 12345,
    credentialDirectory: "/run/credentials/synsec-github",
    postgresUrlEnvironment: "SYNSEC_POSTGRES_URL",
    listenHost: "127.0.0.1",
    port: 8787,
    tlsMode: "terminated-upstream",
    workspaceDirectory: "/var/lib/synsec/workspaces",
    scannerRuntimeCommand: "/usr/bin/docker",
    scannerImage: `ghcr.io/example/synsec-scanners@sha256:${"a".repeat(64)}`,
    operatorStatusPath: "/_synsec/operator/status",
    ...overrides,
  };
}

test("host profile normalizes a complete secret-free production wiring contract", () => {
  assert.deepEqual(parseGitHubAppHostProfile(profile()), {
    version: 1,
    ...profile(),
    interpretation: "secret-free-host-wiring-contract-not-runtime-readiness",
  });
});

test("host profile rejects unknown or missing fields before they can become a credential side channel", () => {
  const marker = "private-key-secret-marker";
  assert.throws(
    () => parseGitHubAppHostProfile({ ...profile(), privateKey: marker }),
    (error) => {
      assert.match(error.message, /exactly the supported non-secret fields/);
      assert.doesNotMatch(error.message, new RegExp(marker));
      return true;
    },
  );
  const missing = profile();
  delete missing.operatorStatusPath;
  assert.throws(() => parseGitHubAppHostProfile(missing), /exactly the supported non-secret fields/);
});

test("host profile accepts only an environment-variable name for PostgreSQL connection lookup", () => {
  assert.throws(
    () => parseGitHubAppHostProfile(profile({ postgresUrlEnvironment: "postgresql://user:secret@db/synsec" })),
    /environment-variable name/,
  );
  assert.throws(() => parseGitHubAppHostProfile(profile({ postgresUrlEnvironment: "synsec_postgres_url" })), /environment-variable name/);
});

test("host profile requires immutable scanner images and one runtime command token", () => {
  assert.throws(() => parseGitHubAppHostProfile(profile({ scannerImage: "ghcr.io/example/scanner:latest" })), /immutable sha256/);
  assert.throws(() => parseGitHubAppHostProfile(profile({ scannerRuntimeCommand: "docker --host tcp://evil" })), /one bounded command token/);
});

test("host profile keeps mounted credentials separate from untrusted repository workspaces", () => {
  assert.throws(
    () => parseGitHubAppHostProfile(profile({
      credentialDirectory: "/var/lib/synsec",
      workspaceDirectory: "/var/lib/synsec/workspaces",
    })),
    /separate, non-nested trees/,
  );
});

test("host profile rejects plaintext production TLS mode, invalid listeners, ports, and replica counts", () => {
  assert.throws(() => parseGitHubAppHostProfile(profile({ tlsMode: "none" })), /TLS mode/);
  assert.throws(() => parseGitHubAppHostProfile(profile({ listenHost: "*" })), /listener/);
  assert.throws(() => parseGitHubAppHostProfile(profile({ port: 70000 })), /listener port/);
  assert.throws(() => parseGitHubAppHostProfile(profile({ replicaCount: 0 })), /replica count/);
});

test("host profile output never contains inline credential or database values", () => {
  const parsed = parseGitHubAppHostProfile(profile());
  const serialized = JSON.stringify(parsed);
  assert.doesNotMatch(serialized, /BEGIN PRIVATE KEY|webhook-secret|postgresql:\/\//i);
  assert.equal(parsed.postgresUrlEnvironment, "SYNSEC_POSTGRES_URL");
});
