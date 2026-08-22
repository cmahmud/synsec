import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { renderRepositoryPostureHtml, writeRepositoryPostureHtml } from "@synsec/repository/posture-html";

const posture = {
  schemaVersion: 1,
  indexedFileCount: 120,
  routeCount: 8,
  routeAuth: {
    "authorization-signal-observed": 2,
    "authentication-signal-observed": 3,
    "no-auth-signal-observed": 3,
  },
  routeSinkKinds: {
    process: 1,
    filesystem: 2,
    database: 4,
    network: 2,
  },
  routesWithSinkSignals: 5,
  routesWithoutAuthSignals: 3,
  interpretation: "bounded-lexical-posture-only",
};

test("repository posture HTML keeps lexical evidence language explicit", () => {
  const html = renderRepositoryPostureHtml(posture);
  assert.match(html, /Bounded lexical repository signals only/);
  assert.match(html, /not runtime exposure/);
  assert.match(html, /120/);
  assert.match(html, /8/);
  assert.match(html, /No auth signal observed/);
  assert.match(html, /<meta name="robots" content="noindex,nofollow">/);
});

test("repository posture HTML writer uses restrictive permissions where supported", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-posture-html-"));
  const path = join(root, "posture", "index.html");
  try {
    await writeRepositoryPostureHtml(path, posture);
    assert.match(await readFile(path, "utf8"), /SynSec repository posture/);
    if (process.platform !== "win32") assert.equal((await stat(path)).mode & 0o777, 0o600);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
