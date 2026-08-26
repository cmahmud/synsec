import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { createGitHubAppInstallationTokenProvider } from "@synsec/github/app-token-provider";
import { createGitHubAppRuntimeCredentialSource } from "@synsec/github/runtime-credentials";

function privateKey() {
  return generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs8", format: "pem" }).toString();
}

function snapshot(generation, key, webhookSecret) {
  return { generation, privateKey: key, webhookSecret };
}

test("runtime credential reload swaps atomically and failed validation preserves the active generation", async () => {
  const key1 = privateKey();
  const key2 = privateKey();
  const source = createGitHubAppRuntimeCredentialSource(snapshot("gen-1", key1, "a".repeat(32)));

  assert.deepEqual(source.getStatus(), {
    version: 1,
    generation: "gen-1",
    webhookSecretCount: 1,
    reloadCount: 0,
    interpretation: "memory-only-runtime-credential-generation",
  });

  await assert.rejects(
    source.reload(async () => snapshot("gen-bad", "not-a-key", "b".repeat(32))),
    /PEM encoded/,
  );
  assert.equal(source.getStatus().generation, "gen-1");
  assert.equal(source.getPrivateKey(), key1);

  const status = await source.reload(async () => snapshot("gen-2", key2, ["b".repeat(32), "a".repeat(32)]));
  assert.equal(status.generation, "gen-2");
  assert.equal(status.reloadCount, 1);
  assert.equal(status.webhookSecretCount, 2);
  assert.equal(source.getPrivateKey(), key2);
  assert.deepEqual(source.getWebhookSecret(), ["b".repeat(32), "a".repeat(32)]);
  assert.doesNotMatch(JSON.stringify(status), /BEGIN PRIVATE KEY|aaaaaaaa|bbbbbbbb/);
});

test("runtime credential reloads serialize and cannot reuse the active generation", async () => {
  const key1 = privateKey();
  const key2 = privateKey();
  const key3 = privateKey();
  const source = createGitHubAppRuntimeCredentialSource(snapshot("gen-1", key1, "a".repeat(32)));
  let releaseFirst;
  const gate = new Promise((resolve) => { releaseFirst = resolve; });
  const order = [];

  const first = source.reload(async () => {
    order.push("first-start");
    await gate;
    order.push("first-end");
    return snapshot("gen-2", key2, "b".repeat(32));
  });
  const second = source.reload(async () => {
    order.push("second-start");
    return snapshot("gen-3", key3, "c".repeat(32));
  });

  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(order, ["first-start"]);
  releaseFirst();
  await Promise.all([first, second]);
  assert.deepEqual(order, ["first-start", "first-end", "second-start"]);
  assert.equal(source.getStatus().generation, "gen-3");
  assert.equal(source.getStatus().reloadCount, 2);
  await assert.rejects(
    source.reload(async () => snapshot("gen-3", key1, "d".repeat(32))),
    /must differ from the active generation/,
  );
  assert.equal(source.getStatus().generation, "gen-3");
});

test("installation token provider resolves the current private key for each operation", async () => {
  const key1 = privateKey();
  const key2 = privateKey();
  const source = createGitHubAppRuntimeCredentialSource(snapshot("gen-1", key1, "a".repeat(32)));
  const appJwts = [];
  const provider = createGitHubAppInstallationTokenProvider({
    appId: 123,
    privateKey: () => source.getPrivateKey(),
    now: () => 1_800_000_000_000,
    exchange: async (_installationId, appJwt) => {
      appJwts.push(appJwt);
      return {
        token: `token-${appJwts.length}`,
        expiresAt: new Date(1_800_000_000_000 + 60 * 60 * 1000).toISOString(),
      };
    },
  });

  assert.equal(await provider(99), "token-1");
  await source.reload(async () => snapshot("gen-2", key2, "b".repeat(32)));
  assert.equal(await provider(99), "token-2");
  assert.equal(appJwts.length, 2);
  assert.notEqual(appJwts[0], appJwts[1]);
});
