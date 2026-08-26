import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";

import { intakeGitHubAppWebhook } from "../packages/github/dist/app-intake.js";

const webhookSecret = "synsec-webhook-secret";

function signature(body) {
  return `sha256=${createHmac("sha256", webhookSecret).update(body).digest("hex")}`;
}

function pullRequestBody(action = "synchronize") {
  return Buffer.from(JSON.stringify({
    action,
    installation: { id: 42 },
    repository: { full_name: "cmahmud/synsec" },
    number: 7,
    pull_request: {
      head: { sha: "abc123" },
      base: { sha: "def456" },
    },
  }));
}

test("app intake verifies before touching replay state", async () => {
  let claims = 0;
  const replayStore = {
    async claim(deliveryId) {
      claims += 1;
      return { accepted: true, deliveryId, receivedAt: new Date().toISOString() };
    },
  };
  const body = pullRequestBody();

  await assert.rejects(() => intakeGitHubAppWebhook({
    body,
    signatureHeader: "sha256=0000000000000000000000000000000000000000000000000000000000000000",
    webhookSecret,
    eventName: "pull_request",
    deliveryId: "delivery-1",
    replayStore,
  }), /signature verification failed/);
  assert.equal(claims, 0);
});

test("app intake makes the first scannable delivery eligible and suppresses duplicates", async () => {
  const seen = new Set();
  const replayStore = {
    async claim(deliveryId) {
      const accepted = !seen.has(deliveryId);
      seen.add(deliveryId);
      return { accepted, deliveryId, receivedAt: "2026-08-22T17:00:00.000Z" };
    },
  };
  const body = pullRequestBody();
  const input = {
    body,
    signatureHeader: signature(body),
    webhookSecret,
    eventName: "pull_request",
    deliveryId: "delivery-1",
    replayStore,
  };

  const first = await intakeGitHubAppWebhook(input);
  assert.equal(first.duplicate, false);
  assert.equal(first.shouldScan, true);
  assert.equal(first.webhook.deliveryId, "delivery-1");

  const duplicate = await intakeGitHubAppWebhook(input);
  assert.equal(duplicate.duplicate, true);
  assert.equal(duplicate.shouldScan, false);
});

test("app intake deduplicates supported bookkeeping events without scanning them", async () => {
  const body = Buffer.from(JSON.stringify({ action: "created", installation: { id: 42 } }));
  const replayStore = {
    async claim(deliveryId) {
      return { accepted: true, deliveryId, receivedAt: "2026-08-22T17:00:00.000Z" };
    },
  };

  const result = await intakeGitHubAppWebhook({
    body,
    signatureHeader: signature(body),
    webhookSecret,
    eventName: "installation",
    deliveryId: "delivery-installation",
    replayStore,
  });
  assert.equal(result.duplicate, false);
  assert.equal(result.shouldScan, false);
});

test("app intake fails closed if replay storage returns a different delivery identity", async () => {
  const body = pullRequestBody();
  const replayStore = {
    async claim() {
      return { accepted: true, deliveryId: "wrong-delivery", receivedAt: "2026-08-22T17:00:00.000Z" };
    },
  };

  await assert.rejects(() => intakeGitHubAppWebhook({
    body,
    signatureHeader: signature(body),
    webhookSecret,
    eventName: "pull_request",
    deliveryId: "delivery-1",
    replayStore,
  }), /mismatched delivery id/);
});

test("app intake redacts credentials from replay backend failures", async () => {
  const body = pullRequestBody();
  const githubToken = `ghp_${"b".repeat(36)}`;
  const replayStore = {
    async claim() {
      throw new Error(`replay database failed token=${githubToken} url=postgres://sync:db-password@db.internal/synsec`);
    },
  };

  let failure;
  try {
    await intakeGitHubAppWebhook({
      body,
      signatureHeader: signature(body),
      webhookSecret,
      eventName: "pull_request",
      deliveryId: "delivery-redaction",
      replayStore,
    });
  } catch (error) {
    failure = error;
  }
  assert.ok(failure instanceof Error);
  assert.match(failure.message, /replay database failed/);
  assert.equal(failure.message.includes(githubToken), false);
  assert.equal(failure.message.includes("db-password"), false);
});
