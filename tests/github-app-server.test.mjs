import assert from "node:assert/strict";
import test from "node:test";
import { createGitHubAppServer } from "@synsec/github/app-server";

async function getJson(url, options) {
  const response = await fetch(url, options);
  return { status: response.status, body: await response.json(), headers: response.headers };
}

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
    getStatus: async () => ({
      installations: { total: 2, active: 1, suspended: 1 },
      queue: { total: 4, pending: 1, leased: 1, failed: 2 },
    }),
  });

  const address = await app.start();
  try {
    const result = await getJson(`http://127.0.0.1:${address.port}/healthz`);
    assert.equal(result.status, 200);
    assert.deepEqual(result.body, {
      status: "ok",
      installations: { total: 2, active: 1, suspended: 1 },
      queue: { total: 4, pending: 1, leased: 1, failed: 2 },
    });
    assert.equal(result.headers.get("cache-control"), "no-store");
    assert.equal(result.headers.get("x-content-type-options"), "nosniff");
    assert.equal(webhookCalls, 0);
  } finally {
    await app.close();
  }
});

test("hosted App server delegates non-health requests and bounds health methods", async () => {
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
    const healthPost = await fetch(`http://127.0.0.1:${address.port}/healthz`, { method: "POST" });
    assert.equal(healthPost.status, 405);
    assert.equal(healthPost.headers.get("allow"), "GET");

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

test("hosted App server rejects unsafe plaintext and malformed TLS configurations", () => {
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
    const result = await getJson(`http://127.0.0.1:${address.port}/healthz`);
    assert.equal(result.status, 503);
    assert.deepEqual(result.body, { status: "unavailable" });
  } finally {
    await app.close();
  }
});
