import assert from "node:assert/strict";
import test from "node:test";
import { createSynSecGitHubAppMaintenanceController } from "@synsec/github/app-maintenance";

function webhookDrain(overrides = {}) {
  let acceptingWebhooks = true;
  let activeWebhookRequests = 0;
  return {
    webhookHandler: async () => {},
    beginDrain() {
      acceptingWebhooks = false;
      return this.status();
    },
    resumeAdmission() {
      acceptingWebhooks = true;
      return this.status();
    },
    status() {
      return { acceptingWebhooks, activeWebhookRequests };
    },
    async waitForDrained() {
      activeWebhookRequests = 0;
    },
    ...overrides,
  };
}

function workerDrain(overrides = {}) {
  let acceptingWorkerRuns = true;
  let activeWorkerRuns = 0;
  return {
    beginDrain() {
      acceptingWorkerRuns = false;
      return this.status();
    },
    resumeAdmission() {
      acceptingWorkerRuns = true;
      return this.status();
    },
    status() {
      return { acceptingWorkerRuns, activeWorkerRuns };
    },
    async run(operation) {
      if (!acceptingWorkerRuns) return { admitted: false };
      activeWorkerRuns += 1;
      try {
        return { admitted: true, value: await operation() };
      } finally {
        activeWorkerRuns -= 1;
      }
    },
    async waitForDrained() {
      activeWorkerRuns = 0;
    },
    ...overrides,
  };
}

test("maintenance closes both admissions and waits for durable fenced leases before stop eligibility", async () => {
  const webhooks = webhookDrain();
  const workers = workerDrain();
  const observations = [2, 1, 0];
  let observationCount = 0;
  const controller = createSynSecGitHubAppMaintenanceController({
    webhookDrain: webhooks,
    workerDrain: workers,
    pollIntervalMs: 10,
    async countActiveLeases() {
      observationCount += 1;
      assert.equal(webhooks.status().acceptingWebhooks, false);
      assert.equal(workers.status().acceptingWorkerRuns, false);
      return observations.shift() ?? 0;
    },
  });

  const evidence = await controller.prepareForServiceStop(1_000);
  assert.equal(observationCount, 3);
  assert.deepEqual(evidence, {
    webhookAdmissionClosed: true,
    workerAdmissionClosed: true,
    localWebhookRequests: 0,
    localWorkerRuns: 0,
    activeLeases: 0,
  });
  assert.deepEqual(controller.status(), {
    acceptingWebhooks: false,
    acceptingWorkerRuns: false,
    activeWebhookRequests: 0,
    activeWorkerRuns: 0,
  });
});

test("maintenance fails closed and suppresses durable-backend diagnostic disclosure", async () => {
  const secretDiagnostic = "postgresql://synsec:super-secret@example.internal/customer";
  const controller = createSynSecGitHubAppMaintenanceController({
    webhookDrain: webhookDrain(),
    workerDrain: workerDrain(),
    async countActiveLeases() {
      throw new Error(secretDiagnostic);
    },
  });

  await assert.rejects(
    controller.prepareForServiceStop(1_000),
    (error) => {
      assert.match(error.message, /durable active-lease observation failed/i);
      assert.doesNotMatch(error.message, /super-secret|example\.internal|customer/);
      return true;
    },
  );
  assert.equal(controller.status().acceptingWebhooks, false);
  assert.equal(controller.status().acceptingWorkerRuns, false);
});

test("maintenance rejects malformed durable lease observations instead of treating them as drain proof", async () => {
  for (const invalid of [-1, 1.5, Number.NaN, 1_000_001]) {
    const controller = createSynSecGitHubAppMaintenanceController({
      webhookDrain: webhookDrain(),
      workerDrain: workerDrain(),
      async countActiveLeases() {
        return invalid;
      },
    });
    await assert.rejects(controller.prepareForServiceStop(1_000), /active-lease observation failed/i);
  }
});

test("maintenance can explicitly resume both admission boundaries after an aborted service operation", () => {
  const controller = createSynSecGitHubAppMaintenanceController({
    webhookDrain: webhookDrain(),
    workerDrain: workerDrain(),
    async countActiveLeases() {
      return 0;
    },
  });

  controller.beginDrain();
  assert.equal(controller.status().acceptingWebhooks, false);
  assert.equal(controller.status().acceptingWorkerRuns, false);
  const resumed = controller.resumeAdmission();
  assert.equal(resumed.acceptingWebhooks, true);
  assert.equal(resumed.acceptingWorkerRuns, true);
});

test("maintenance validates polling and timeout bounds before relying on operator configuration", async () => {
  assert.throws(
    () => createSynSecGitHubAppMaintenanceController({
      webhookDrain: webhookDrain(),
      workerDrain: workerDrain(),
      pollIntervalMs: 1,
      async countActiveLeases() { return 0; },
    }),
    /poll interval/i,
  );

  const controller = createSynSecGitHubAppMaintenanceController({
    webhookDrain: webhookDrain(),
    workerDrain: workerDrain(),
    async countActiveLeases() { return 0; },
  });
  await assert.rejects(controller.prepareForServiceStop(1), /maintenance timeout/i);
});
