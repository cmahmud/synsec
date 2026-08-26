import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";

import { createGitHubAppWebhookHttpHandler } from "@synsec/github/app-http";

const secret = "synsec-http-webhook-secret";
const headSha = "0123456789abcdef0123456789abcdef01234567";
const baseSha = "abcdef0123456789abcdef0123456789abcdef01";

function signature(body) {
  return `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
}

function pullRequestBody() {
  return Buffer.from(JSON.stringify({
    action: "synchronize",
    installation: { id: 7 },
    repository: { full_name: "cmahmud/synsec", clone_url: "https://attacker.invalid/repo.git" },
    number: 2,
    pull_request: { head: { sha: headSha }, base: { sha: baseSha } },
  }));
}

class ReplayStore {
  constructor() { this.claims = new Map(); }
  async claim(deliveryId) {
    const existing = this.claims.get(deliveryId);
    if (existing) return { accepted: false, deliveryId, receivedAt: existing };
    const receivedAt = "2026-08-22T19:10:00.000Z";
    this.claims.set(deliveryId, receivedAt);
    return { accepted: true, deliveryId, receivedAt };
  }
  async release(deliveryId, receivedAt) {
    if (this.claims.get(deliveryId) !== receivedAt) return false;
    this.claims.delete(deliveryId);
    return true;
  }
}

class InstallationStore {
  async get() { return undefined; }
  async put(input) { return { version: 1, repositories: [], updatedAt: new Date().toISOString(), ...input }; }
  async remove() { return false; }
  async isRepositoryAllowed(id, repository) { return id === 7 && repository === "cmahmud/synsec"; }
}

function request(body, overrides = {}) {
  const headers = {
    "content-type": "application/json",
    "content-length": String(body.byteLength),
    "x-hub-signature-256": signature(body),
    "x-github-event": "pull_request",
    "x-github-delivery": "delivery-http-1",
    ...(overrides.headers ?? {}),
  };
  return {
    url: overrides.url ?? "/github/webhooks",
    method: overrides.method ?? "POST",
    headers,
    async *[Symbol.asyncIterator]() {
      if (body.byteLength > 0) yield body;
    },
  };
}

function response() {
  return {
    statusCode: 0,
    headers: new Map(),
    body: "",
    setHeader(name, value) { this.headers.set(String(name).toLowerCase(), value); },
    end(body = "") { this.body = String(body); },
  };
}

test("HTTP webhook endpoint queues an authorized commit-pinned delivery with a minimal response", async () => {
  const replayStore = new ReplayStore();
  const queued = [];
  const handler = createGitHubAppWebhookHttpHandler({
    webhookSecret: secret,
    replayStore,
    installationStore: new InstallationStore(),
    queue: {
      async enqueue(input) {
        queued.push(input);
        return { version: 1, jobId: "c".repeat(32), ...input, createdAt: new Date().toISOString(), attempts: 0, status: "pending" };
      },
    },
  });
  const body = pullRequestBody();
  const res = response();
  await handler(request(body), res);

  assert.equal(res.statusCode, 202);
  assert.deepEqual(JSON.parse(res.body), { status: "queued" });
  assert.equal(res.headers.get("cache-control"), "no-store");
  assert.equal(queued.length, 1);
  assert.equal(queued[0].headSha, headSha);
  assert.equal(JSON.stringify(queued[0]).includes("attacker.invalid"), false);
});

test("HTTP webhook endpoint rejects wrong methods, media types, missing headers, and oversized bodies before durable processing", async () => {
  let claims = 0;
  const replayStore = new ReplayStore();
  replayStore.claim = async (...args) => { claims += 1; return ReplayStore.prototype.claim.apply(replayStore, args); };
  const handler = createGitHubAppWebhookHttpHandler({
    webhookSecret: secret,
    replayStore,
    installationStore: new InstallationStore(),
    queue: { async enqueue() { throw new Error("must not enqueue"); } },
  });
  const body = pullRequestBody();

  const methodRes = response();
  await handler(request(body, { method: "GET" }), methodRes);
  assert.equal(methodRes.statusCode, 405);

  const mediaRes = response();
  await handler(request(body, { headers: { "content-type": "text/plain" } }), mediaRes);
  assert.equal(mediaRes.statusCode, 415);

  const missingRes = response();
  await handler(request(body, { headers: { "x-github-delivery": "" } }), missingRes);
  assert.equal(missingRes.statusCode, 400);

  const largeRes = response();
  await handler(request(Buffer.alloc(0), { headers: { "content-length": String(10 * 1024 * 1024 + 1) } }), largeRes);
  assert.equal(largeRes.statusCode, 413);
  assert.equal(claims, 0);
});

test("HTTP webhook endpoint hides durable failure details, redacts operator callbacks, and leaves the delivery retryable", async () => {
  const replayStore = new ReplayStore();
  const errors = [];
  let attempts = 0;
  const githubToken = `ghp_${"a".repeat(36)}`;
  const credentialUrl = "postgres://db-user:queue-password@db.internal/synsec";
  const handler = createGitHubAppWebhookHttpHandler({
    webhookSecret: secret,
    replayStore,
    installationStore: new InstallationStore(),
    queue: {
      async enqueue(input) {
        attempts += 1;
        if (attempts === 1) throw new Error(`queue unavailable token=${githubToken} backend=${credentialUrl}`);
        return { version: 1, jobId: "d".repeat(32), ...input, createdAt: new Date().toISOString(), attempts: 0, status: "pending" };
      },
    },
    onError: (error) => errors.push(error),
  });
  const body = pullRequestBody();
  const req = request(body, { headers: { "x-github-delivery": "delivery-http-retry" } });

  const first = response();
  await handler(req, first);
  assert.equal(first.statusCode, 500);
  assert.deepEqual(JSON.parse(first.body), { status: "error" });
  assert.equal(first.body.includes(githubToken), false);
  assert.equal(first.body.includes("queue-password"), false);
  assert.equal(replayStore.claims.has("delivery-http-retry"), false);
  assert.equal(errors.length, 1);
  const callbackMessage = errors[0] instanceof Error ? errors[0].message : String(errors[0]);
  assert.equal(callbackMessage.includes(githubToken), false);
  assert.equal(callbackMessage.includes("queue-password"), false);
  assert.match(callbackMessage, /queue unavailable/);

  const second = response();
  await handler(request(body, { headers: { "x-github-delivery": "delivery-http-retry" } }), second);
  assert.equal(second.statusCode, 202);
  assert.equal(attempts, 2);
});
