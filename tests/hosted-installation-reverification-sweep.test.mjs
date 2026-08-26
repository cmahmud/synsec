import assert from "node:assert/strict";
import test from "node:test";
import {
  runSynSecHostedInstallationReverificationSweep,
  SynSecHostedInstallationReverificationSweepController,
} from "@synsec/github/hosted-installation-reverification-sweep";

function target(installationId, tenantId = `tenant-${installationId}`) {
  return {
    principal: {
      subject: `subject-${installationId}`,
      tenantId,
      githubUserId: 1000 + installationId,
    },
    installationId,
  };
}

function storeFor(results = new Map()) {
  return {
    async beginReverification(tenantId, installationId, githubUserId) {
      return {
        epoch: installationId,
        tenantId,
        installationId,
        githubUserId,
        accountId: 2000 + installationId,
        accountType: "Organization",
      };
    },
    async finishVerified(input) {
      return results.get(input.installationId) ?? "applied";
    },
    async finishRevoked(input) {
      return results.get(input.installationId) ?? "applied";
    },
    async isFreshlyAuthorized() {
      return true;
    },
  };
}

function transportFor(targetValue, behavior = "verified") {
  return {
    async getAuthenticatedUser() {
      return {
        id: targetValue.principal.githubUserId,
        login: `user-${targetValue.installationId}`,
      };
    },
    async getAccessibleInstallation() {
      if (behavior === "inaccessible") return undefined;
      return {
        id: targetValue.installationId,
        account: {
          id: 2000 + targetValue.installationId,
          login: `org-${targetValue.installationId}`,
          type: "Organization",
        },
        repositorySelection: "selected",
      };
    },
  };
}

test("re-verification sweep returns only aggregate evidence and respects bounded concurrency", async () => {
  const targets = [target(1), target(2), target(3), target(4)];
  let active = 0;
  let maximumActive = 0;
  const result = await runSynSecHostedInstallationReverificationSweep({
    concurrency: 2,
    store: storeFor(new Map([[3, "stale"]])),
    provider: {
      async listTargets() {
        return targets;
      },
      async createTransport(targetValue) {
        active += 1;
        maximumActive = Math.max(maximumActive, active);
        await new Promise((resolve) => setTimeout(resolve, 5));
        active -= 1;
        return transportFor(targetValue, targetValue.installationId === 2 ? "inaccessible" : "verified");
      },
    },
  });

  assert.deepEqual(result, {
    status: "completed",
    attempted: 4,
    verified: 2,
    revoked: 1,
    superseded: 1,
    failed: 0,
    interpretation: "scheduler-observation-only-not-authorization-evidence",
  });
  assert.equal(maximumActive, 2);
  const serialized = JSON.stringify(result);
  assert.doesNotMatch(serialized, /tenant-|subject-|org-|user-/);
});

test("re-verification sweep rejects duplicate tenant installation targets before credentials are requested", async () => {
  let transportCalls = 0;
  await assert.rejects(
    runSynSecHostedInstallationReverificationSweep({
      store: storeFor(),
      provider: {
        async listTargets() {
          return [target(10, "tenant-a"), target(10, "tenant-a")];
        },
        async createTransport(targetValue) {
          transportCalls += 1;
          return transportFor(targetValue);
        },
      },
    }),
    /duplicate tenant installation/,
  );
  assert.equal(transportCalls, 0);
});

test("target discovery errors are categorical and do not reflect backend details", async () => {
  await assert.rejects(
    runSynSecHostedInstallationReverificationSweep({
      store: storeFor(),
      provider: {
        async listTargets() {
          throw new Error("postgresql://secret-user:secret-pass@db.internal/tenant-data");
        },
        async createTransport() {
          throw new Error("not reached");
        },
      },
    }),
    (error) => {
      assert.equal(error.message, "Hosted installation re-verification target discovery failed.");
      assert.doesNotMatch(error.message, /postgresql|secret|tenant-data/);
      return true;
    },
  );
});

test("per-target credential or transport failures are counted without disclosure", async () => {
  const result = await runSynSecHostedInstallationReverificationSweep({
    store: storeFor(),
    provider: {
      async listTargets() {
        return [target(21), target(22)];
      },
      async createTransport(targetValue) {
        if (targetValue.installationId === 21) {
          throw new Error("github-token ghp_supersecret transport failed for tenant-21");
        }
        return transportFor(targetValue);
      },
    },
  });
  assert.equal(result.failed, 1);
  assert.equal(result.verified, 1);
  assert.doesNotMatch(JSON.stringify(result), /ghp_|supersecret|tenant-21/);
});

test("process-local controller coalesces overlapping sweeps and exposes only aggregate scheduler status", async () => {
  let targetDiscoveryCalls = 0;
  let releaseDiscovery;
  const discoveryGate = new Promise((resolve) => {
    releaseDiscovery = resolve;
  });
  const controller = new SynSecHostedInstallationReverificationSweepController({
    store: storeFor(),
    provider: {
      async listTargets() {
        targetDiscoveryCalls += 1;
        await discoveryGate;
        return [target(31)];
      },
      async createTransport(targetValue) {
        return transportFor(targetValue);
      },
    },
  });

  const first = controller.runOnce();
  const second = controller.runOnce();
  assert.equal(first, second);
  assert.deepEqual(controller.status(), {
    active: true,
    completedSweeps: 0,
    interpretation: "process-local-scheduler-status-only",
  });

  releaseDiscovery();
  const result = await first;
  assert.equal(targetDiscoveryCalls, 1);
  assert.equal(result.verified, 1);
  assert.deepEqual(controller.status(), {
    active: false,
    completedSweeps: 1,
    lastResult: result,
    interpretation: "process-local-scheduler-status-only",
  });
});

test("sweep validates concurrency before target discovery", async () => {
  let discovered = false;
  assert.throws(
    () => new SynSecHostedInstallationReverificationSweepController({
      concurrency: 33,
      store: storeFor(),
      provider: {
        async listTargets() {
          discovered = true;
          return [];
        },
        async createTransport(targetValue) {
          return transportFor(targetValue);
        },
      },
    }),
    /concurrency must be between 1 and 32/,
  );
  assert.equal(discovered, false);
});
