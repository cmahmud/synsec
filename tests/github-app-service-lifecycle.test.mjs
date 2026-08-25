import assert from "node:assert/strict";
import test from "node:test";
import { EventEmitter } from "node:events";
import {
  bindSynSecGitHubAppServiceSignals,
  createSynSecGitHubAppServiceLifecycleController,
} from "@synsec/github/app-service-lifecycle";

function stopEvidence() {
  return {
    webhookAdmissionClosed: true,
    workerAdmissionClosed: true,
    localWebhookRequests: 0,
    localWorkerRuns: 0,
    activeLeases: 0,
  };
}

function maintenance(overrides = {}) {
  return {
    prepareCalls: 0,
    resumeCalls: 0,
    async prepareForServiceStop() {
      this.prepareCalls += 1;
      return stopEvidence();
    },
    resumeAdmission() {
      this.resumeCalls += 1;
    },
    ...overrides,
  };
}

test("service lifecycle serializes concurrent stop requests and hands off only after drain evidence", async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const control = maintenance({
    async prepareForServiceStop() {
      this.prepareCalls += 1;
      await gate;
      return stopEvidence();
    },
  });
  const handoffs = [];
  const lifecycle = createSynSecGitHubAppServiceLifecycleController({
    maintenance: control,
    onReadyToStop(evidence, reason) {
      handoffs.push({ evidence, reason });
    },
  });

  const first = lifecycle.requestStop("SIGTERM");
  const second = lifecycle.requestStop("SIGINT");
  assert.equal(lifecycle.status().state, "draining");
  assert.equal(control.prepareCalls, 1);
  release();

  assert.deepEqual(await first, { state: "ready-to-stop", reason: "SIGTERM" });
  assert.deepEqual(await second, { state: "ready-to-stop", reason: "SIGTERM" });
  assert.equal(handoffs.length, 1);
  assert.equal(handoffs[0].reason, "SIGTERM");
  assert.deepEqual(handoffs[0].evidence, stopEvidence());
  assert.equal(control.prepareCalls, 1);
});

test("service lifecycle fails closed and does not expose maintenance diagnostics", async () => {
  const control = maintenance({
    async prepareForServiceStop() {
      this.prepareCalls += 1;
      throw new Error("postgresql://user:secret@example.internal/customer");
    },
  });
  let readyCalls = 0;
  let failedReason;
  const lifecycle = createSynSecGitHubAppServiceLifecycleController({
    maintenance: control,
    onReadyToStop() { readyCalls += 1; },
    onStopFailed(reason) { failedReason = reason; },
  });

  const result = await lifecycle.requestStop("operator");
  assert.deepEqual(result, { state: "stop-failed", reason: "operator" });
  assert.equal(readyCalls, 0);
  assert.equal(failedReason, "operator");
  assert.equal(JSON.stringify(result).includes("secret"), false);
  assert.equal(control.resumeCalls, 0);

  assert.deepEqual(lifecycle.resume(), { state: "running" });
  assert.equal(control.resumeCalls, 1);
});

test("service lifecycle treats a failing hosting handoff as a failed stop and can resume", async () => {
  const control = maintenance();
  const lifecycle = createSynSecGitHubAppServiceLifecycleController({
    maintenance: control,
    async onReadyToStop() {
      throw new Error("system manager detail should not escape");
    },
  });

  assert.deepEqual(await lifecycle.requestStop("SIGTERM"), { state: "stop-failed", reason: "SIGTERM" });
  assert.deepEqual(lifecycle.resume(), { state: "running" });
  assert.equal(control.resumeCalls, 1);
});

test("service lifecycle cannot resume after stop eligibility has been handed off", async () => {
  const lifecycle = createSynSecGitHubAppServiceLifecycleController({
    maintenance: maintenance(),
    onReadyToStop() {},
  });
  await lifecycle.requestStop();
  assert.throws(() => lifecycle.resume(), /already ready to stop/);
});

test("SIGTERM and SIGINT bindings invoke the same serialized lifecycle boundary and dispose cleanly", async () => {
  const source = new EventEmitter();
  const reasons = [];
  const controller = {
    async requestStop(reason) {
      reasons.push(reason);
      return { state: "ready-to-stop", reason };
    },
  };
  const binding = bindSynSecGitHubAppServiceSignals(controller, source);

  source.emit("SIGTERM");
  source.emit("SIGINT");
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(reasons, ["SIGTERM", "SIGINT"]);

  binding.dispose();
  binding.dispose();
  source.emit("SIGTERM");
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(reasons, ["SIGTERM", "SIGINT"]);
});

test("service lifecycle validates bounded timeout configuration", () => {
  assert.throws(
    () => createSynSecGitHubAppServiceLifecycleController({
      maintenance: maintenance(),
      timeoutMs: 99,
      onReadyToStop() {},
    }),
    /service stop timeout/,
  );
});
