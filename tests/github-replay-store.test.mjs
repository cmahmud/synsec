import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileGitHubWebhookReplayStore } from "../packages/github/dist/replay-store.js";

const HOUR = 60 * 60 * 1000;

test("replay store accepts one delivery and rejects a duplicate atomically", async () => {
  const directory = await mkdtemp(join(tmpdir(), "synsec-replay-"));
  const now = Date.UTC(2026, 7, 22, 17, 0, 0);
  const store = new FileGitHubWebhookReplayStore(directory, { now: () => now, retentionMs: HOUR });

  const claims = await Promise.all(Array.from({ length: 8 }, () => store.claim("01234567-89ab-cdef-0123-456789abcdef")));
  assert.equal(claims.filter((claim) => claim.accepted).length, 1);
  assert.equal(claims.filter((claim) => !claim.accepted).length, 7);

  const files = await readdir(directory);
  assert.equal(files.length, 1);
  assert.match(files[0], /^[a-f0-9]{64}\.json$/);
  assert.equal(files[0].includes("01234567"), false);

  const record = JSON.parse(await readFile(join(directory, files[0]), "utf8"));
  assert.equal(record.deliveryId, "01234567-89ab-cdef-0123-456789abcdef");
  assert.equal(record.receivedAt, new Date(now).toISOString());
  if (process.platform !== "win32") {
    const mode = (await stat(join(directory, files[0]))).mode & 0o777;
    assert.equal(mode, 0o600);
  }
});

test("replay store permits reuse only after bounded retention expires", async () => {
  const directory = await mkdtemp(join(tmpdir(), "synsec-replay-expiry-"));
  let now = Date.UTC(2026, 7, 22, 17, 0, 0);
  const store = new FileGitHubWebhookReplayStore(directory, { now: () => now, retentionMs: HOUR });

  assert.equal((await store.claim("delivery-1")).accepted, true);
  now += HOUR - 1;
  assert.equal((await store.claim("delivery-1")).accepted, false);
  now += 2;
  assert.equal((await store.claim("delivery-1")).accepted, true);
});

test("replay store validates ids and retention bounds", async () => {
  const directory = await mkdtemp(join(tmpdir(), "synsec-replay-validation-"));
  assert.throws(() => new FileGitHubWebhookReplayStore(directory, { retentionMs: HOUR - 1 }), /retention must be an integer/);

  const store = new FileGitHubWebhookReplayStore(directory, { retentionMs: HOUR });
  await assert.rejects(() => store.claim("../delivery"), /unsupported characters/);
  await assert.rejects(() => store.claim("x".repeat(129)), /exceeds 128 characters/);
});

test("replay store rejects corrupt existing records instead of treating them as duplicates", async () => {
  const directory = await mkdtemp(join(tmpdir(), "synsec-replay-corrupt-"));
  const now = Date.UTC(2026, 7, 22, 17, 0, 0);
  const store = new FileGitHubWebhookReplayStore(directory, { now: () => now, retentionMs: HOUR });
  await store.claim("delivery-corrupt");

  const [file] = await readdir(directory);
  const { writeFile } = await import("node:fs/promises");
  await writeFile(join(directory, file), "not json", "utf8");

  await assert.rejects(() => store.claim("delivery-corrupt"), /invalid JSON/);
});

test("pruneExpired removes only old replay marker files", async () => {
  const directory = await mkdtemp(join(tmpdir(), "synsec-replay-prune-"));
  let now = Date.UTC(2026, 7, 22, 17, 0, 0);
  const store = new FileGitHubWebhookReplayStore(directory, { now: () => now, retentionMs: HOUR });
  await store.claim("delivery-old");
  now += HOUR + 1;
  assert.equal(await store.pruneExpired(), 1);
  assert.deepEqual(await readdir(directory), []);
});
