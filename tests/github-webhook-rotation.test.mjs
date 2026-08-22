import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";

import {
  parseVerifiedGitHubAppWebhook,
  verifyGitHubWebhookSignature,
} from "@synsec/github/app";

const oldSecret = "o".repeat(32);
const newSecret = "n".repeat(32);
const body = JSON.stringify({
  after: "0123456789abcdef0123456789abcdef01234567",
  installation: { id: 42 },
  repository: { full_name: "cmahmud/synsec" },
});

function signature(secret) {
  return `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
}

test("webhook rotation pair accepts either active secret without changing normalized event identity", () => {
  assert.equal(verifyGitHubWebhookSignature(body, signature(newSecret), [newSecret, oldSecret]), true);
  assert.equal(verifyGitHubWebhookSignature(body, signature(oldSecret), [newSecret, oldSecret]), true);

  const webhook = parseVerifiedGitHubAppWebhook({
    body,
    signatureHeader: signature(oldSecret),
    webhookSecret: [newSecret, oldSecret],
    eventName: "push",
    deliveryId: "delivery-rotation",
  });
  assert.deepEqual(webhook, {
    event: "push",
    deliveryId: "delivery-rotation",
    installationId: 42,
    repository: "cmahmud/synsec",
    headSha: "0123456789abcdef0123456789abcdef01234567",
  });
});

test("webhook rotation remains bounded and rejects duplicate or oversized secret sets", () => {
  assert.throws(
    () => verifyGitHubWebhookSignature(body, signature(newSecret), []),
    /between 1 and 2 secrets/,
  );
  assert.throws(
    () => verifyGitHubWebhookSignature(body, signature(newSecret), [newSecret, oldSecret, "x".repeat(32)]),
    /between 1 and 2 secrets/,
  );
  assert.throws(
    () => verifyGitHubWebhookSignature(body, signature(newSecret), [newSecret, newSecret]),
    /contains duplicates/,
  );
});

test("a secret outside the configured rotation pair is rejected", () => {
  assert.equal(
    verifyGitHubWebhookSignature(body, signature("x".repeat(32)), [newSecret, oldSecret]),
    false,
  );
});
