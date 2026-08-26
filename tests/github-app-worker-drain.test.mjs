import assert from "node:assert/strict";
import test from "node:test";

import { createSynSecGitHubAppWorkerDrainController } from "@synsec/github/app-worker-drain";
import { runConfiguredGitHubAppWorkerOnce } from "@synsec/github/app-worker-runner";

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

test("worker drain closes new admission while allowing an admitted operation to finish", async () => {
  const controller = createSynSecGitHubAppWorkerDrainController();
  const entered = deferred();
  const finish = deferred();

  const active = controller.run(async () => {
    entered.resolve();
    await finish.promise;
    return "complete";
  });
  await entered.promise;

  assert.deepEqual(controller.beginDrain(), { acceptingWorkerRuns: false, activeWorkerRuns: 1 });
  const rejected = await controller.run(async () => { throw new Error("draining operation must not execute"); });
  assert.deepEqual(rejected, { admitted: false });

  const drained = controller.waitForDrained();
  finish.resolve();
  assert.deepEqual(await active, { admitted: true, value: "complete" });
  await drained;
  assert.deepEqual(controller.status(), { acceptingWorkerRuns: false, activeWorkerRuns: 0 });

  controller.resumeAdmission();
  assert.deepEqual(await controller.run(async () => "resumed"), { admitted: true, value: "resumed" });
});

test("waitForDrained fails closed while worker admission remains open", async () => {
  const controller = createSynSecGitHubAppWorkerDrainController();
  await assert.rejects(controller.waitForDrained(), /admission must be draining/);
});

test("configured worker checks drain before queue claim admission", async () => {
  const controller = createSynSecGitHubAppWorkerDrainController();
  controller.beginDrain();
  let claims = 0;

  const result = await runConfiguredGitHubAppWorkerOnce({
    workerDrain: controller,
    queue: {
      async claimNext() { claims += 1; return undefined; },
      async assertLease() { throw new Error("must not assert lease"); },
      async release() { throw new Error("must not release"); },
      async fail() { throw new Error("must not fail"); },
      async complete() { throw new Error("must not complete"); },
    },
    installationStore: { isRepositoryAllowed: async () => true },
    config: { scanners: ["opengrep"], parallelism: 1 },
    getInstallationToken: async () => { throw new Error("must not request token"); },
  });

  assert.deepEqual(result, { status: "draining" });
  assert.equal(claims, 0);
});
