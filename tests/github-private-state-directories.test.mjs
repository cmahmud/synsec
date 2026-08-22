import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { FileGitHubInstallationStore } from "@synsec/github/installation-store";
import { FileGitHubWebhookReplayStore } from "@synsec/github/replay-store";
import { FileGitHubScanQueue } from "@synsec/github/scan-queue";

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
