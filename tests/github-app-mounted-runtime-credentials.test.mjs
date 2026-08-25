import assert from "node:assert/strict";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadMountedGitHubAppRuntimeCredentialSnapshot } from "@synsec/github/mounted-runtime-credentials";
import { createGitHubAppRuntimeCredentialSource } from "@synsec/github/runtime-credentials";

const PRIVATE_KEY_A = "-----BEGIN PRIVATE KEY-----\nalpha\n-----END PRIVATE KEY-----\n";
const PRIVATE_KEY_B = "-----BEGIN PRIVATE KEY-----\nbeta\n-----END PRIVATE KEY-----\n";
const SECRET_A = "a".repeat(32);
const SECRET_B = "b".repeat(32);
const SECRET_C = "c".repeat(32);

async function makeMount() {
  const root = await mkdtemp(join(tmpdir(), "synsec-mounted-github-credentials-"));
  return { root, cleanup: () => rm(root, { recursive: true, force: true }) };
}

async function writeSnapshot(root, { generation, privateKey, secret, previousSecret }) {
  await writeFile(join(root, "generation"), `${generation}\n`, "utf8");
  await writeFile(join(root, "private-key.pem"), privateKey, "utf8");
  await writeFile(join(root, "webhook-secret"), `${secret}\n`, "utf8");
  if (previousSecret !== undefined) {
    await writeFile(join(root, "webhook-secret-previous"), `${previousSecret}\n`, "utf8");
  }
}

test("mounted credential source reads fixed bounded files with optional rotation overlap", async () => {
  const mount = await makeMount();
  try {
    await writeSnapshot(mount.root, {
      generation: "gen-1",
      privateKey: PRIVATE_KEY_A,
      secret: SECRET_A,
      previousSecret: SECRET_B,
    });
    const snapshot = await loadMountedGitHubAppRuntimeCredentialSnapshot(mount.root);
    assert.equal(snapshot.generation, "gen-1");
    assert.equal(snapshot.privateKey, PRIVATE_KEY_A);
    assert.deepEqual(snapshot.webhookSecret, [SECRET_A, SECRET_B]);
  } finally {
    await mount.cleanup();
  }
});

test("mounted credential source supports a single active webhook secret", async () => {
  const mount = await makeMount();
  try {
    await writeSnapshot(mount.root, {
      generation: "gen-single",
      privateKey: PRIVATE_KEY_A,
      secret: SECRET_A,
    });
    const snapshot = await loadMountedGitHubAppRuntimeCredentialSnapshot(mount.root);
    assert.equal(snapshot.webhookSecret, SECRET_A);
  } finally {
    await mount.cleanup();
  }
});

test("mounted credential reload swaps atomically and failed mounted validation preserves the active generation", async () => {
  const mount = await makeMount();
  try {
    await writeSnapshot(mount.root, {
      generation: "gen-1",
      privateKey: PRIVATE_KEY_A,
      secret: SECRET_A,
    });
    const source = createGitHubAppRuntimeCredentialSource(
      await loadMountedGitHubAppRuntimeCredentialSnapshot(mount.root),
    );

    await writeSnapshot(mount.root, {
      generation: "gen-2",
      privateKey: PRIVATE_KEY_B,
      secret: SECRET_B,
      previousSecret: SECRET_A,
    });
    const status = await source.reload(() => loadMountedGitHubAppRuntimeCredentialSnapshot(mount.root));
    assert.equal(status.generation, "gen-2");
    assert.equal(status.reloadCount, 1);
    assert.equal(source.getPrivateKey(), PRIVATE_KEY_B);
    assert.deepEqual(source.getWebhookSecret(), [SECRET_B, SECRET_A]);

    await writeFile(join(mount.root, "webhook-secret"), "too-short\n", "utf8");
    await assert.rejects(
      source.reload(() => loadMountedGitHubAppRuntimeCredentialSnapshot(mount.root)),
      /webhook secret must contain between 32 and 4096 bytes/,
    );
    assert.equal(source.getStatus().generation, "gen-2");
    assert.equal(source.getStatus().reloadCount, 1);
    assert.equal(source.getPrivateKey(), PRIVATE_KEY_B);
  } finally {
    await mount.cleanup();
  }
});

test("mounted credential source rejects relative directories, symlinks, and oversized files", async () => {
  await assert.rejects(
    loadMountedGitHubAppRuntimeCredentialSnapshot("relative/secrets"),
    /must be an absolute path/,
  );

  const mount = await makeMount();
  const outside = await makeMount();
  try {
    await writeSnapshot(mount.root, {
      generation: "gen-1",
      privateKey: PRIVATE_KEY_A,
      secret: SECRET_A,
    });
    await writeFile(join(outside.root, "secret"), SECRET_C, "utf8");
    await rm(join(mount.root, "webhook-secret"));
    await symlink(join(outside.root, "secret"), join(mount.root, "webhook-secret"));
    await assert.rejects(
      loadMountedGitHubAppRuntimeCredentialSnapshot(mount.root),
      /regular non-symlink files/,
    );

    await rm(join(mount.root, "webhook-secret"));
    await writeFile(join(mount.root, "webhook-secret"), "x".repeat(4097), "utf8");
    await assert.rejects(
      loadMountedGitHubAppRuntimeCredentialSnapshot(mount.root),
      /violates its byte bound/,
    );
  } finally {
    await mount.cleanup();
    await outside.cleanup();
  }
});

test("mounted credential source errors do not reflect mount paths or credential contents", async () => {
  const mount = await makeMount();
  const marker = "super-secret-value-that-must-not-leak";
  try {
    await writeFile(join(mount.root, "generation"), "gen-1\n", "utf8");
    await writeFile(join(mount.root, "private-key.pem"), PRIVATE_KEY_A, "utf8");
    await writeFile(join(mount.root, "webhook-secret"), marker.repeat(200), "utf8");
    try {
      await loadMountedGitHubAppRuntimeCredentialSnapshot(mount.root);
      assert.fail("expected mounted credential load to fail");
    } catch (error) {
      const message = String(error?.message ?? error);
      assert.doesNotMatch(message, new RegExp(marker));
      assert.doesNotMatch(message, new RegExp(mount.root.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    }
  } finally {
    await mount.cleanup();
  }
});
