import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, generateKeyPairSync, verify as cryptoVerify } from "node:crypto";

import {
  createGitHubAppJwt,
  createGitHubInstallationToken,
  parseVerifiedGitHubAppWebhook,
  shouldScanGitHubAppWebhook,
  verifyGitHubWebhookSignature,
} from "../packages/github/dist/app.js";

const webhookSecret = "synsec-webhook-secret";

function signature(body) {
  return `sha256=${createHmac("sha256", webhookSecret).update(body).digest("hex")}`;
}

test("verifyGitHubWebhookSignature validates the exact payload bytes", () => {
  const body = Buffer.from('{"repository":{"full_name":"cmahmud/synsec"}}');
  assert.equal(verifyGitHubWebhookSignature(body, signature(body), webhookSecret), true);
  assert.equal(verifyGitHubWebhookSignature(Buffer.from(`${body} `), signature(body), webhookSecret), false);
  assert.equal(verifyGitHubWebhookSignature(body, "sha256=not-a-signature", webhookSecret), false);
});

test("parseVerifiedGitHubAppWebhook normalizes pull requests without trusting payload URLs", () => {
  const body = Buffer.from(JSON.stringify({
    action: "synchronize",
    installation: { id: 42 },
    repository: {
      full_name: "cmahmud/synsec",
      clone_url: "https://attacker.invalid/repository.git",
    },
    number: 7,
    pull_request: {
      head: { sha: "abc123", repo: { clone_url: "https://attacker.invalid/head.git" } },
      base: { sha: "def456" },
    },
  }));

  assert.deepEqual(parseVerifiedGitHubAppWebhook({
    body,
    signatureHeader: signature(body),
    webhookSecret,
    eventName: "pull_request",
    deliveryId: "delivery-1",
  }), {
    event: "pull_request",
    action: "synchronize",
    deliveryId: "delivery-1",
    installationId: 42,
    repository: "cmahmud/synsec",
    headSha: "abc123",
    baseSha: "def456",
    pullRequestNumber: 7,
  });
});

test("parseVerifiedGitHubAppWebhook rejects unsupported, unsigned, or incomplete events", () => {
  const body = Buffer.from(JSON.stringify({ installation: { id: 1 } }));
  assert.throws(() => parseVerifiedGitHubAppWebhook({
    body,
    signatureHeader: signature(body),
    webhookSecret,
    eventName: "issues",
  }), /Unsupported GitHub App event/);

  assert.throws(() => parseVerifiedGitHubAppWebhook({
    body,
    signatureHeader: "sha256=0000000000000000000000000000000000000000000000000000000000000000",
    webhookSecret,
    eventName: "installation",
  }), /signature verification failed/);

  const incomplete = Buffer.from(JSON.stringify({ installation: { id: 1 }, repository: { full_name: "cmahmud/synsec" } }));
  assert.throws(() => parseVerifiedGitHubAppWebhook({
    body: incomplete,
    signatureHeader: signature(incomplete),
    webhookSecret,
    eventName: "push",
  }), /missing required repository, installation, or commit identity/);
});

test("shouldScanGitHubAppWebhook allows only push and selected PR lifecycle events", () => {
  const pr = {
    event: "pull_request",
    action: "synchronize",
    installationId: 42,
    repository: "cmahmud/synsec",
    headSha: "abc123",
    baseSha: "def456",
    pullRequestNumber: 7,
  };

  assert.equal(shouldScanGitHubAppWebhook(pr), true);
  assert.equal(shouldScanGitHubAppWebhook({ ...pr, action: "closed" }), false);
  assert.equal(shouldScanGitHubAppWebhook({ ...pr, action: "converted_to_draft" }), false);
  assert.equal(shouldScanGitHubAppWebhook({ ...pr, headSha: undefined }), false);
  assert.equal(shouldScanGitHubAppWebhook({
    event: "push",
    installationId: 42,
    repository: "cmahmud/synsec",
    headSha: "abc123",
  }), true);
  assert.equal(shouldScanGitHubAppWebhook({
    event: "installation",
    action: "created",
    installationId: 42,
  }), false);
  assert.equal(shouldScanGitHubAppWebhook({
    event: "installation_repositories",
    action: "added",
    installationId: 42,
  }), false);
});

test("createGitHubAppJwt creates a short-lived verifiable RS256 token", () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
  const now = Date.UTC(2026, 7, 22, 16, 0, 0);
  const token = createGitHubAppJwt(12345, privatePem, now);
  const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");
  const header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString("utf8"));
  const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8"));

  assert.deepEqual(header, { alg: "RS256", typ: "JWT" });
  assert.equal(payload.iss, "12345");
  assert.equal(payload.iat, Math.floor(now / 1000) - 30);
  assert.equal(payload.exp - payload.iat, 9 * 60);
  assert.equal(cryptoVerify(
    "RSA-SHA256",
    Buffer.from(`${encodedHeader}.${encodedPayload}`),
    publicKey,
    Buffer.from(encodedSignature, "base64url"),
  ), true);
});

test("createGitHubInstallationToken posts only to the fixed GitHub installation endpoint", async () => {
  let request;
  const fakeFetch = async (url, init) => {
    request = { url, init };
    return new Response(JSON.stringify({ token: "installation-token", expires_at: "2026-08-22T17:00:00Z" }), { status: 201 });
  };

  const result = await createGitHubInstallationToken(42, "app-jwt", { fetch: fakeFetch });
  assert.equal(request.url, "https://api.github.com/app/installations/42/access_tokens");
  assert.equal(request.init.method, "POST");
  assert.equal(request.init.redirect, "error");
  assert.equal(request.init.headers.Authorization, "Bearer app-jwt");
  assert.equal(request.init.body, "{}");
  assert.deepEqual(result, { token: "installation-token", expiresAt: "2026-08-22T17:00:00Z" });
});

test("installation-token errors do not expose the app JWT", async () => {
  const secretJwt = "secret-app-jwt";
  const fakeFetch = async () => new Response(JSON.stringify({ message: "Bad credentials" }), { status: 401 });
  await assert.rejects(
    () => createGitHubInstallationToken(42, secretJwt, { fetch: fakeFetch }),
    (error) => {
      assert.match(error.message, /HTTP 401/);
      assert.equal(error.message.includes(secretJwt), false);
      return true;
    },
  );
});
