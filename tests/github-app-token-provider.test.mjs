import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import { createGitHubAppInstallationTokenProvider } from "@synsec/github/app-token-provider";

function privateKeyPem() {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return privateKey.export({ type: "pkcs8", format: "pem" });
}

test("App token provider signs a fresh short-lived JWT per operation without caching installation tokens", async () => {
  let now = Date.UTC(2026, 7, 22, 19, 30, 0);
  const exchanges = [];
  const provider = createGitHubAppInstallationTokenProvider({
    appId: 12345,
    privateKey: privateKeyPem(),
    now: () => now,
    exchange: async (installationId, jwt) => {
      const payload = JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString("utf8"));
      exchanges.push({ installationId, jwt, payload });
      return {
        token: `installation-token-${exchanges.length}`,
        expiresAt: new Date(now + 60 * 60 * 1000).toISOString(),
      };
    },
  });

  assert.equal(await provider(42), "installation-token-1");
  now += 1_000;
  assert.equal(await provider(42), "installation-token-2");
  assert.equal(exchanges.length, 2);
  assert.notEqual(exchanges[0].jwt, exchanges[1].jwt);
  assert.equal(exchanges[0].payload.iss, "12345");
  assert.equal(exchanges[1].payload.iat - exchanges[0].payload.iat, 1);
});

test("App token provider rejects malformed or nearly expired token metadata", async () => {
  const now = Date.UTC(2026, 7, 22, 19, 30, 0);
  const key = privateKeyPem();
  const invalidExpiry = createGitHubAppInstallationTokenProvider({
    appId: 1,
    privateKey: key,
    now: () => now,
    exchange: async () => ({ token: "secret", expiresAt: "not-a-time" }),
  });
  await assert.rejects(() => invalidExpiry(1), /invalid expiration timestamp/);

  const expiring = createGitHubAppInstallationTokenProvider({
    appId: 1,
    privateKey: key,
    now: () => now,
    minRemainingMs: 30_000,
    exchange: async () => ({ token: "secret", expiresAt: new Date(now + 29_999).toISOString() }),
  });
  await assert.rejects(() => expiring(1), /expires too soon/);
});

test("App token provider bounds private-key and lifetime configuration before exchange", () => {
  assert.throws(() => createGitHubAppInstallationTokenProvider({
    appId: 1,
    privateKey: "x".repeat(64 * 1024 + 1),
  }), /private key exceeds/);
  assert.throws(() => createGitHubAppInstallationTokenProvider({
    appId: 1,
    privateKey: privateKeyPem(),
    minRemainingMs: 600_001,
  }), /minimum remaining lifetime/);
});
