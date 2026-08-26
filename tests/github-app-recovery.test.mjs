import assert from "node:assert/strict";
import test from "node:test";
import { createSynSecGitHubAppRecoveryController } from "@synsec/github/app-recovery";

function maintenance(initial = {}) {
  let status = {
    acceptingWebhooks: true,
    acceptingWorkerRuns: true,
    activeWebhookRequests: 0,
    activeWorkerRuns: 0,
    ...initial,
  };
  return {
    beginCalls: 0,
    resumeCalls: 0,
    beginDrain() {
      this.beginCalls += 1;
      status = { ...status, acceptingWebhooks: false, acceptingWorkerRuns: false };
      return { ...status };
    },
    resumeAdmission() {
      this.resumeCalls += 1;
      status = { ...status, acceptingWebhooks: true, acceptingWorkerRuns: true };
      return { ...status };
    },
    status() { return { ...status }; },
    setStatus(next) { status = { ...status, ...next }; },
  };
}

const ready = {
  sharedStateReady: true,
  runtimeCredentialsReady: true,
  githubControlPlaneReady: true,
};

test("recovery isolation immediately closes both local admission boundaries", () => {
  const control = maintenance();
  const recovery = createSynSecGitHubAppRecoveryController({ maintenance: control, async probe() { return ready; } });

  const result = recovery.isolate("shared-state-unavailable");
  assert.equal(control.beginCalls, 1);
  assert.equal(control.status().acceptingWebhooks, false);
  assert.equal(control.status().acceptingWorkerRuns, false);
  assert.equal(result.state, "isolated");
  assert.equal(result.reason, "shared-state-unavailable");
  assert.equal(result.attempts, 0);
  assert.equal(JSON.stringify(result).includes("credential"), false);
});

test("recovery waits for locally admitted work before touching trusted probes", async () => {
  const control = maintenance({ activeWebhookRequests: 1, activeWorkerRuns: 1 });
  let probes = 0;
  const recovery = createSynSecGitHubAppRecoveryController({
    maintenance: control,
    pollIntervalMs: 10,
    async probe() { probes += 1; return ready; },
  });
  recovery.isolate("operator");
  const pending = recovery.recover(500);
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.equal(probes, 0);
  assert.equal(control.resumeCalls, 0);

  control.setStatus({ activeWebhookRequests: 0, activeWorkerRuns: 0 });
  const result = await pending;
  assert.equal(probes, 1);
  assert.equal(control.resumeCalls, 1);
  assert.equal(result.state, "running");
  assert.equal(result.reason, undefined);
});

test("recovery retries explicit not-ready observations but resumes only after one fully-ready observation", async () => {
  const control = maintenance();
  const observations = [
    { ...ready, sharedStateReady: false },
    { ...ready, runtimeCredentialsReady: false },
    ready,
  ];
  const recovery = createSynSecGitHubAppRecoveryController({
    maintenance: control,
    pollIntervalMs: 10,
    async probe() { return observations.shift(); },
  });
  recovery.isolate("runtime-credentials-unavailable");

  const result = await recovery.recover(500);
  assert.equal(result.state, "running");
  assert.equal(result.attempts, 3);
  assert.equal(control.resumeCalls, 1);
});

test("thrown or malformed probe failures remain categorical and keep admission closed", async () => {
  for (const probe of [
    async () => { throw new Error("postgresql://user:secret@db.internal/customer"); },
    async () => ({ sharedStateReady: true }),
  ]) {
    const control = maintenance();
    const recovery = createSynSecGitHubAppRecoveryController({ maintenance: control, probe });
    recovery.isolate("github-control-plane-unavailable");
    const result = await recovery.recover(500);
    assert.equal(result.state, "recovery-failed");
    assert.equal(control.resumeCalls, 0);
    assert.equal(control.status().acceptingWebhooks, false);
    assert.equal(control.status().acceptingWorkerRuns, false);
    assert.equal(JSON.stringify(result).includes("secret"), false);
    assert.equal(JSON.stringify(result).includes("postgresql"), false);
  }
});

test("concurrent recovery callers share one verification attempt", async () => {
  const control = maintenance();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let probes = 0;
  const recovery = createSynSecGitHubAppRecoveryController({
    maintenance: control,
    async probe() {
      probes += 1;
      await gate;
      return ready;
    },
  });
  recovery.isolate("operator");
  const first = recovery.recover(500);
  const second = recovery.recover(500);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(probes, 1);
  release();
  assert.deepEqual(await first, await second);
  assert.equal(control.resumeCalls, 1);
});

test("recovery fails closed if admission reopens outside the controller", async () => {
  const control = maintenance();
  let probes = 0;
  const recovery = createSynSecGitHubAppRecoveryController({
    maintenance: control,
    async probe() { probes += 1; return ready; },
  });
  recovery.isolate("operator");
  control.resumeAdmission();
  const result = await recovery.recover(500);
  assert.equal(result.state, "recovery-failed");
  assert.equal(probes, 0);
});

test("recovery validates bounded configuration and categorical incident reasons", () => {
  const control = maintenance();
  assert.throws(
    () => createSynSecGitHubAppRecoveryController({ maintenance: control, pollIntervalMs: 9, async probe() { return ready; } }),
    /recovery poll interval/,
  );
  const recovery = createSynSecGitHubAppRecoveryController({ maintenance: control, async probe() { return ready; } });
  assert.throws(() => recovery.isolate("repo-secret-value"), /recovery reason is invalid/);
  recovery.isolate("operator");
  assert.throws(() => recovery.recover(99), /recovery timeout/);
});
