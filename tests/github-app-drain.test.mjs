import assert from "node:assert/strict";
import test from "node:test";
import { createSynSecGitHubAppDrainController } from "@synsec/github/app-drain";

function responseRecorder() {
  const headers = new Map();
  return {
    statusCode: 200,
    body: "",
    ended: false,
    setHeader(name, value) { headers.set(String(name).toLowerCase(), String(value)); },
    getHeader(name) { return headers.get(String(name).toLowerCase()); },
    end(body = "") { this.body += String(body); this.ended = true; },
  };
}

test("drain rejects new webhook admission with retryable aggregate-only response", async () => {
  let invoked = 0;
  const controller = createSynSecGitHubAppDrainController(async () => { invoked += 1; });
  controller.beginDrain();
  const response = responseRecorder();
  await controller.webhookHandler({}, response);

  assert.equal(invoked, 0);
  assert.equal(response.statusCode, 503);
  assert.equal(response.getHeader("retry-after"), "1");
  assert.equal(response.getHeader("cache-control"), "no-store");
  assert.equal(response.body, '{"status":"draining"}\n');
  assert.deepEqual(controller.status(), { acceptingWebhooks: false, activeWebhookRequests: 0 });
});

test("request admitted before drain is allowed to finish and waitForDrained observes it", async () => {
  let release;
  const blocked = new Promise((resolve) => { release = resolve; });
  const controller = createSynSecGitHubAppDrainController(async () => { await blocked; });
  const first = controller.webhookHandler({}, responseRecorder());
  assert.equal(controller.status().activeWebhookRequests, 1);

  controller.beginDrain();
  const rejected = responseRecorder();
  await controller.webhookHandler({}, rejected);
  assert.equal(rejected.statusCode, 503);
  assert.equal(controller.status().activeWebhookRequests, 1);

  let drained = false;
  const waiting = controller.waitForDrained(5_000).then(() => { drained = true; });
  await Promise.resolve();
  assert.equal(drained, false);
  release();
  await first;
  await waiting;
  assert.deepEqual(controller.status(), { acceptingWebhooks: false, activeWebhookRequests: 0 });
});

test("admission can be resumed explicitly after a drain", async () => {
  let invoked = 0;
  const controller = createSynSecGitHubAppDrainController(async () => { invoked += 1; });
  controller.beginDrain();
  controller.resumeAdmission();
  await controller.webhookHandler({}, responseRecorder());
  assert.equal(invoked, 1);
  assert.deepEqual(controller.status(), { acceptingWebhooks: true, activeWebhookRequests: 0 });
});

test("invalid drain timeouts are rejected without invoking the webhook handler", async () => {
  let release;
  const blocked = new Promise((resolve) => { release = resolve; });
  const controller = createSynSecGitHubAppDrainController(async () => { await blocked; });
  const inFlight = controller.webhookHandler({}, responseRecorder());
  await assert.rejects(controller.waitForDrained(999), /drain timeout/);
  release();
  await inFlight;
});
