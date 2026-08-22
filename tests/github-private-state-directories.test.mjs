import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { FileGitHubInstallationStore } from "@synsec/github/installation-store";
import { FileGitHubWebhookReplayStore } from "@synsec/github/replay-store";
import { FileGitHubScanQueue } from "@synsec/github/scan-queue";
import { ensurePrivateDirectory } from "../packages/github/dist/private-directory.js";

const symlinkError = /real directory|EEXIST|not a directory/i;

test("GitHub durable stores repair permissive pre-existing directories where supported", async () => {
  if (process.platform === "win32") return;
  const root = await mkdtemp(join(tmpdir(), "synsec-private-state-"));
  const installationDirectory = join(root, "installations");
  const replayDirectory = join(root, "replay");
  const queueDirectory = join(root, "queue");

  try {
    for (const directory of [installationDirectory, replayDirectory, queueDirectory]) {
      await mkdir(directory, { recursive: true, mode: 0o755 });
      await chmod(directory, 0o755);
      assert.equal((await stat(directory)).mode & 0o777, 0o755);
    }

    const installations = new FileGitHubInstallationStore(installationDirectory);
    await installations.put({
      installationId: 1,
      accountLogin: "example",
      accountType: "Organization",
      repositorySelection: "selected",
      repositories: ["example/repo"],
    });

    const replay = new FileGitHubWebhookReplayStore(replayDirectory);
    assert.equal((await replay.claim("delivery-private-mode")).accepted, true);

    const queue = new FileGitHubScanQueue(queueDirectory);
    await queue.enqueue({
      deliveryId: "queue-private-mode",
      installationId: 1,
      repository: "example/repo",
      headSha: "a".repeat(40),
      event: "push",
    });

    for (const directory of [installationDirectory, replayDirectory, queueDirectory]) {
      assert.equal((await stat(directory)).mode & 0o777, 0o700);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("private durable directory handling refuses a symlink final path", async () => {
  if (process.platform === "win32") return;
  const root = await mkdtemp(join(tmpdir(), "synsec-private-state-symlink-"));
  const realDirectory = join(root, "real");
  const linkedDirectory = join(root, "linked");
  try {
    await mkdir(realDirectory, { mode: 0o755 });
    await symlink(realDirectory, linkedDirectory, "dir");
    await assert.rejects(() => ensurePrivateDirectory(linkedDirectory), symlinkError);
    assert.equal((await stat(realDirectory)).mode & 0o777, 0o755);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("durable stores validate a symlink directory even when the first operation is a read or release", async () => {
  if (process.platform === "win32") return;
  const root = await mkdtemp(join(tmpdir(), "synsec-private-state-first-access-"));
  const realDirectory = join(root, "real");
  const linkedDirectory = join(root, "linked");
  try {
    await mkdir(realDirectory, { mode: 0o755 });
    await symlink(realDirectory, linkedDirectory, "dir");

    const installations = new FileGitHubInstallationStore(linkedDirectory);
    await assert.rejects(() => installations.get(1), symlinkError);
    await assert.rejects(() => installations.remove(1), symlinkError);

    const replay = new FileGitHubWebhookReplayStore(linkedDirectory);
    await assert.rejects(
      () => replay.release("delivery-first-access", "2026-08-22T21:00:00.000Z"),
      symlinkError,
    );

    const queue = new FileGitHubScanQueue(linkedDirectory);
    await assert.rejects(() => queue.deleteFailed("a".repeat(32)), symlinkError);

    assert.equal((await stat(realDirectory)).mode & 0o777, 0o755);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("durable stores refuse symlink-shaped record files", async () => {
  if (process.platform === "win32") return;
  const root = await mkdtemp(join(tmpdir(), "synsec-private-record-symlink-"));
  const installationDirectory = join(root, "installations");
  const replayDirectory = join(root, "replay");
  const queueDirectory = join(root, "queue");
  const target = join(root, "target.json");
  const deliveryId = "delivery-record-symlink";
  const replayName = `${createHash("sha256").update(deliveryId).digest("hex")}.json`;
  const queueId = "a".repeat(32);

  try {
    await writeFile(target, "{}\n", "utf8");
    for (const directory of [installationDirectory, replayDirectory, queueDirectory]) {
      await mkdir(directory, { recursive: true, mode: 0o700 });
    }
    await symlink(target, join(installationDirectory, "1.json"));
    await symlink(target, join(replayDirectory, replayName));
    await symlink(target, join(queueDirectory, `${queueId}.json`));

    const installations = new FileGitHubInstallationStore(installationDirectory);
    await assert.rejects(() => installations.get(1), /symlinked/);
    await assert.rejects(() => installations.remove(1), /symlinked/);

    const replay = new FileGitHubWebhookReplayStore(replayDirectory);
    await assert.rejects(
      () => replay.release(deliveryId, "2026-08-22T21:00:00.000Z"),
      /symlinked/,
    );

    const queue = new FileGitHubScanQueue(queueDirectory);
    await assert.rejects(() => queue.deleteFailed(queueId), /symlinked/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
