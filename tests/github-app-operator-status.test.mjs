import assert from "node:assert/strict";
import test from "node:test";
import {
  buildGitHubAppOperatorStatusSnapshot,
  createGitHubAppOperatorStatusHttpHandler,
} from "@synsec/github/app-operator-status";

function observation(overrides = {}) {
  return {
    releaseId: "synsec-v0.2.0+9435694",
    schemaVersion: 1,
    ready: true,
    credentialStatus: {
      version: 1,
      generation: "vault:2026-08-25T14:00Z",
      webhookSecretCount: 2,
      reloadCount: 4,
      interpretation: "memory-only-runtime-credential-generation",
    },
    webhookAdmission: "open",
    workerAdmission: "open",
    activeWebhookRequests: 2,
    activeWorkerRuns: 1,
    durableActiveLeases: 3,
    recoveryPhase: "idle",
    observedAt: "2026-08-25T14:00:00.000Z",
    ...overrides,
  };
}

function responseRecorder() {
  const headers = new Map();
  let body = "";
  const response = {
    statusCode: 0,
    setHeader(name, value) { headers.set(String(name).toLowerCase(), String(value)); },
    end(value = "") { body = String(value); },
  };
  return { response, headers, getBody: () => body };
}

test("operator snapshot exposes only fixed aggregate fields", () => {
  const snapshot = buildGitHubAppOperatorStatusSnapshot({
    ...observation(),
    backendUrl: "postgresql://secret@example/db",
    tenantId: "tenant-secret-marker",
    privateKey: "private-key-marker",
  });
  assert.deepEqual(snapshot, {
    version: 1,
    release: { id: "synsec-v0.2.0+9435694", schemaVersion: 1 },
    ready: true,
    credentials: { generation: "vault:2026-08-25T14:00Z", webhookSecretCount: 2, reloadCount: 4 },
    admission: { webhook: "open", worker: "open", activeWebhookRequests: 2, activeWorkerRuns: 1 },
    durable: { activeLeases: 3 },
    recovery: { phase: "idle" },
    observedAt: "2026-08-25T14:00:00.000Z",
    interpretation: "aggregate-operator-observation-not-external-security-proof",
  });
  const serialized = JSON.stringify(snapshot);
  assert.doesNotMatch(serialized, /secret@example|tenant-secret-marker|private-key-marker/);
});

test("operator snapshot rejects malformed identifiers, counters, credential status, and recovery state", () => {
  assert.throws(() => buildGitHubAppOperatorStatusSnapshot(observation({ releaseId: "secret value with spaces" })), /release id/);
  assert.throws(() => buildGitHubAppOperatorStatusSnapshot(observation({ durableActiveLeases: -1 })), /active lease count/);
  assert.throws(() => buildGitHubAppOperatorStatusSnapshot(observation({ recoveryPhase: "unknown" })), /recovery phase/);
  assert.throws(() => buildGitHubAppOperatorStatusSnapshot(observation({
    credentialStatus: { ...observation().credentialStatus, webhookSecretCount: 3 },
  })), /secret count/);
});

test("operator HTTP handler hides endpoint from unauthorized callers and never observes state", async () => {
  let observed = 0;
  const handler = createGitHubAppOperatorStatusHttpHandler({
    authorize: async () => false,
    observe: async () => { observed += 1; return observation(); },
  });
  const recorder = responseRecorder();
  await handler({ method: "GET", url: "/_synsec/operator/status" }, recorder.response);
  assert.equal(recorder.response.statusCode, 404);
  assert.deepEqual(JSON.parse(recorder.getBody()), { status: "not_found" });
  assert.equal(observed, 0);
  assert.equal(recorder.headers.get("cache-control"), "no-store");
});

test("operator HTTP handler returns the bounded snapshot after authorization", async () => {
  const handler = createGitHubAppOperatorStatusHttpHandler({
    authorize: () => true,
    observe: () => observation(),
  });
  const recorder = responseRecorder();
  await handler({ method: "GET", url: "/_synsec/operator/status?ignored=1" }, recorder.response);
  assert.equal(recorder.response.statusCode, 200);
  const payload = JSON.parse(recorder.getBody());
  assert.equal(payload.release.id, "synsec-v0.2.0+9435694");
  assert.equal(payload.durable.activeLeases, 3);
  assert.equal(payload.credentials.webhookSecretCount, 2);
  assert.equal(recorder.headers.get("x-content-type-options"), "nosniff");
});

test("authorization exceptions fail closed without reflecting secret-bearing errors", async () => {
  const errors = [];
  const handler = createGitHubAppOperatorStatusHttpHandler({
    authorize: async () => { throw new Error("Bearer secret-auth-marker"); },
    observe: () => observation(),
    onError: (error) => errors.push(error.message),
  });
  const recorder = responseRecorder();
  await handler({ method: "GET", url: "/_synsec/operator/status" }, recorder.response);
  assert.equal(recorder.response.statusCode, 404);
  assert.doesNotMatch(recorder.getBody(), /secret-auth-marker/);
  assert.deepEqual(errors, ["GitHub App operator status authorization_failed."]);
});

test("observation exceptions return categorical unavailable without reflecting backend diagnostics", async () => {
  const errors = [];
  const handler = createGitHubAppOperatorStatusHttpHandler({
    authorize: () => true,
    observe: async () => { throw new Error("postgresql://user:password@db/tenant-secret"); },
    onError: (error) => errors.push(error.message),
  });
  const recorder = responseRecorder();
  await handler({ method: "GET", url: "/_synsec/operator/status" }, recorder.response);
  assert.equal(recorder.response.statusCode, 503);
  assert.deepEqual(JSON.parse(recorder.getBody()), { status: "unavailable" });
  assert.doesNotMatch(recorder.getBody(), /password|tenant-secret/);
  assert.deepEqual(errors, ["GitHub App operator status observation_failed."]);
});

test("operator status path and method are bounded", async () => {
  assert.throws(() => createGitHubAppOperatorStatusHttpHandler({
    path: "relative",
    authorize: () => true,
    observe: () => observation(),
  }), /bounded absolute path/);

  const handler = createGitHubAppOperatorStatusHttpHandler({ authorize: () => true, observe: () => observation() });
  const recorder = responseRecorder();
  await handler({ method: "POST", url: "/_synsec/operator/status" }, recorder.response);
  assert.equal(recorder.response.statusCode, 405);
  assert.equal(recorder.headers.get("allow"), "GET");
});
