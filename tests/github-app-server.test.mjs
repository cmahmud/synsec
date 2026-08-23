import assert from "node:assert/strict";
import test from "node:test";
import { createGitHubAppServer } from "@synsec/github/app-server";

async function getJson(url, options) {
  const response = await fetch(url, options);
  return { status: response.status, body: await response.json(), headers: response.headers };
}

const healthyStatus = {
  installations: {
    total: 2,
    active: 1,
    suspended: 1,
    allRepositories: 1,
    selectedRepositories: 1,
  },
  queue: { total: 4, pending: 1, leased: 1, expiredLeases: 1, failed: 2 },
};

test("hosted App server exposes aggregate-only health on loopback", async () => {
  let webhookCalls = 0;
  const app = createGitHubAppServer({
    host: "127.0.0.1",
    port: 0,
    tlsMode: "none",
    webhookHandler: async (_request, response) => {
      webhookCalls += 1;
      response.statusCode = 204;
      response.end();
    },
    getStatus: async () => healthyStatus,
  });

  const address = await app.start();
  try {
    const result = await getJson(`http://127.0.0.1:${address.port}/healthz`);
    assert.equal(result.status, 200);
    assert.deepEqual(result.body, {
      status: "ok",
      ...healthyStatus,
    });
    assert.equal(result.headers.get("cache-control"), "no-store");
    assert.equal(result.headers.get("x-content-type-options"), "nosniff");
    assert.equal(webhookCalls, 0);
  } finally {
    await app.close();
  }
});

test("hosted App server exposes a minimal routing-readiness probe", async () => {
  let webhookCalls = 0;
  let statusCalls = 0;
  const app = createGitHubAppServer({
    host: "127.0.0.1",
    port: 0,
    tlsMode: "none",
    webhookHandler: async (_request, response) => {
      webhookCalls += 1;
      response.end();
    },
    getStatus: async () => {
      statusCalls += 1;
      return healthyStatus;
    },
    isReady: (status) => status.queue.expiredLeases === 0,
  });

  const address = await app.start();
  try {
    const result = await getJson(`http://127.0.0.1:${address.port}/readyz`);
    assert.equal(result.status, 503);
    assert.deepEqual(result.body, { status: "not_ready" });
    assert.equal(result.headers.get("cache-control"), "no-store");
    assert.equal(statusCalls, 1);
    assert.equal(webhookCalls, 0);

    const health = await getJson(`http://127.0.0.1:${address.port}/healthz`);
    assert.equal(health.status, 200);
    assert.equal(health.body.status, "ok");
  } finally {
    await app.close();
  }
});

test("hosted App readiness fails closed on status or policy errors without leaking diagnostics", async () => {
  const secret = "https://operator:super-secret@db.internal/runtime";
  for (const failureMode of ["status", "policy"]) {
    const app = createGitHubAppServer({
      host: "127.0.0.1",
      port: 0,
      tlsMode: "none",
      webhookHandler: async (_request, response) => response.end(),
      getStatus: async () => {
        if (failureMode === "status") throw new Error(secret);
        return healthyStatus;
      },
      isReady: () => {
        if (failureMode === "policy") throw new Error(secret);
        return true;
      },
    });
    const address = await app.start();
    try {
      const result = await getJson(`http://127.0.0.1:${address.port}/readyz`);
      assert.equal(result.status, 503);
      assert.deepEqual(result.body, { status: "not_ready" });
      assert.doesNotMatch(JSON.stringify(result.body), /super-secret|db\.internal/);
    } finally {
      await app.close();
    }
  }
});

test("hosted App server delegates non-probe requests and bounds probe methods", async () => {
  let seenUrl;
  const app = createGitHubAppServer({
    host: "127.0.0.1",
    port: 0,
    tlsMode: "none",
    webhookHandler: async (request, response) => {
      seenUrl = request.url;
      response.statusCode = 202;
      response.end("queued");
    },
  });
  const address = await app.start();
  try {
    for (const path of ["healthz", "readyz"]) {
      const probePost = await fetch(`http://127.0.0.1:${address.port}/${path}`, { method: "POST" });
      assert.equal(probePost.status, 405);
      assert.equal(probePost.headers.get("allow"), "GET");
    }

    const readiness = await getJson(`http://127.0.0.1:${address.port}/readyz`);
    assert.equal(readiness.status, 200);
    assert.deepEqual(readiness.body, { status: "ready" });

    const webhook = await fetch(`http://127.0.0.1:${address.port}/github/webhooks`, {
      method: "POST",
      body: "{}",
      headers: { "content-type": "application/json" },
    });
    assert.equal(webhook.status, 202);
    assert.equal(await webhook.text(), "queued");
    assert.equal(seenUrl, "/github/webhooks");
  } finally {
    await app.close();
  }
});

test("hosted App server bounds concurrent webhook work and keeps probes available", async () => {
  let webhookCalls = 0;
  let releaseFirst;
  const firstMayFinish = new Promise((resolve) => { releaseFirst = resolve; });
  let firstStartedResolve;
  const firstStarted = new Promise((resolve) => { firstStartedResolve = resolve; });

  const app = createGitHubAppServer({
    host: "127.0.0.1",
    port: 0,
    tlsMode: "none",
    maxConcurrentWebhooks: 1,
    webhookHandler: async (_request, response) => {
      webhookCalls += 1;
      firstStartedResolve();
      await firstMayFinish;
      response.statusCode = 202;
      response.end("queued");
    },
    getStatus: async () => healthyStatus,
  });
  const address = await app.start();
  try {
    const first = fetch(`http://127.0.0.1:${address.port}/github/webhooks`, {
      method: "POST",
      body: "first",
    });
    await firstStarted;

    const busy = await getJson(`http://127.0.0.1:${address.port}/github/webhooks`, {
      method: "POST",
      body: "second",
    });
    assert.equal(busy.status, 503);
    assert.deepEqual(busy.body, { status: "busy" });
    assert.equal(busy.headers.get("retry-after"), "1");
    assert.equal(webhookCalls, 1);

    const health = await getJson(`http://127.0.0.1:${address.port}/healthz`);
    assert.equal(health.status, 200);
    assert.equal(health.body.status, "ok");

    const readiness = await getJson(`http://127.0.0.1:${address.port}/readyz`);
    assert.equal(readiness.status, 200);
    assert.deepEqual(readiness.body, { status: "ready" });

    releaseFirst();
    const firstResponse = await first;
    assert.equal(firstResponse.status, 202);
    assert.equal(await firstResponse.text(), "queued");
  } finally {
    releaseFirst?.();
    await app.close();
  }
});

test("hosted App server rejects unsafe plaintext and malformed TLS, probe, or concurrency configurations", () => {
  const handler = async (_request, response) => response.end();
  assert.throws(() => createGitHubAppServer({
    host: "0.0.0.0",
    port: 3000,
    tlsMode: "none",
    webhookHandler: handler,
  }), /only on loopback/);

  assert.throws(() => createGitHubAppServer({
    host: "127.0.0.1",
    port: 3000,
    tlsMode: "local",
    webhookHandler: handler,
  }), /requires both key and certificate/);

  assert.throws(() => createGitHubAppServer({
    host: "127.0.0.1",
    port: 3000,
    tlsMode: "none",
    tls: { key: "key", cert: "cert" },
    webhookHandler: handler,
  }), /accepted only in local TLS mode/);

  for (const maxConcurrentWebhooks of [0, 1.5, 1001]) {
    assert.throws(() => createGitHubAppServer({
      host: "127.0.0.1",
      port: 3000,
      tlsMode: "none",
      maxConcurrentWebhooks,
      webhookHandler: handler,
    }), /concurrent webhook limit/);
  }

  for (const [field, value] of [["healthPath", "healthz"], ["readinessPath", "/readyz?verbose=1"]]) {
    assert.throws(() => createGitHubAppServer({
      host: "127.0.0.1",
      port: 3000,
      tlsMode: "none",
      [field]: value,
      webhookHandler: handler,
    }), /must be an absolute path without query, fragment, or control components/);
  }

  assert.throws(() => createGitHubAppServer({
    host: "127.0.0.1",
    port: 3000,
    tlsMode: "none",
    healthPath: "/probe",
    readinessPath: "/probe",
    webhookHandler: handler,
  }), /must be distinct/);

  assert.throws(() => createGitHubAppServer({
    host: "127.0.0.1",
    port: 3000,
    tlsMode: "none",
    webhookHandler: handler,
    isReady: () => true,
  }), /requires aggregate runtime status collection/);
});

test("hosted App server returns unavailable when status collection fails", async () => {
  const app = createGitHubAppServer({
    host: "127.0.0.1",
    port: 0,
    tlsMode: "none",
    webhookHandler: async (_request, response) => response.end(),
    getStatus: async () => {
      throw new Error("durable state unavailable");
    },
  });
  const address = await app.start();
  try {
    const health = await getJson(`http://127.0.0.1:${address.port}/healthz`);
    assert.equal(health.status, 503);
    assert.deepEqual(health.body, { status: "unavailable" });

    const readiness = await getJson(`http://127.0.0.1:${address.port}/readyz`);
    assert.equal(readiness.status, 503);
    assert.deepEqual(readiness.body, { status: "not_ready" });
  } finally {
    await app.close();
  }
});
