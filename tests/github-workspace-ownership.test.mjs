import assert from "node:assert/strict";
import { access, mkdir, mkdtemp, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  markGitHubWorkspaceOwned,
  reconcileGitHubOwnedWorkspaces,
} from "@synsec/github/workspace-ownership";

const hour = 60 * 60 * 1000;
const now = Date.parse("2026-08-22T20:00:00.000Z");

async function ownedWorkspace(root, name, createdAt) {
  const workspace = join(root, name);
  await mkdir(workspace, { mode: 0o700 });
  await markGitHubWorkspaceOwned(workspace, () => createdAt);
  return workspace;
}

test("workspace reconciliation observes valid owned workspaces without deleting by default", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-workspace-observe-"));
  const stale = await ownedWorkspace(root, "synsec-github-stale", now - 2 * hour);
  const fresh = await ownedWorkspace(root, "synsec-github-fresh", now - 30 * 60 * 1000);

  const result = await reconcileGitHubOwnedWorkspaces(root, {
    retentionMs: hour,
    now: () => now,
  });

  assert.deepEqual(result, { inspected: 2, owned: 2, stale: 1, deleted: 0, skipped: 0 });
  await access(stale);
  await access(fresh);
});

test("workspace reconciliation deletes only stale directories with valid ownership markers", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-workspace-delete-"));
  const stale = await ownedWorkspace(root, "synsec-github-owned", now - 2 * hour);
  const unrelated = join(root, "synsec-github-unowned");
  await mkdir(unrelated);
  await writeFile(join(unrelated, "keep.txt"), "keep");
  await mkdir(join(root, "not-synsec"));

  const result = await reconcileGitHubOwnedWorkspaces(root, {
    retentionMs: hour,
    deleteOwned: true,
    now: () => now,
  });

  assert.deepEqual(result, { inspected: 2, owned: 1, stale: 1, deleted: 1, skipped: 1 });
  await assert.rejects(() => access(stale), /ENOENT/);
  await access(unrelated);
  await access(join(root, "not-synsec"));
});

test("workspace reconciliation refuses malformed markers and symlink-shaped candidates", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "synsec-workspace-unsafe-"));
  const malformed = join(root, "synsec-github-malformed");
  await mkdir(malformed);
  await writeFile(join(malformed, ".synsec-workspace.json"), JSON.stringify({ version: 1, workspaceId: "bad", createdAt: "nope" }));

  if (process.platform !== "win32") {
    const target = join(root, "target");
    await mkdir(target);
    await symlink(target, join(root, "synsec-github-link"), "dir");
  } else {
    t.diagnostic("directory symlink assertion skipped on Windows");
  }

  const result = await reconcileGitHubOwnedWorkspaces(root, {
    retentionMs: hour,
    deleteOwned: true,
    now: () => now,
  });

  assert.equal(result.deleted, 0);
  assert.equal(result.owned, 0);
  assert.ok(result.skipped >= 1);
  await access(malformed);
});

test("workspace reconciliation bounds retention and deletion batches", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-workspace-bounds-"));
  for (let index = 0; index < 3; index += 1) {
    await ownedWorkspace(root, `synsec-github-${index}`, now - 2 * hour);
  }

  const result = await reconcileGitHubOwnedWorkspaces(root, {
    retentionMs: hour,
    maxDeletes: 2,
    deleteOwned: true,
    now: () => now,
  });
  assert.equal(result.stale, 3);
  assert.equal(result.deleted, 2);

  await assert.rejects(() => reconcileGitHubOwnedWorkspaces(root, { retentionMs: hour - 1 }), /retention/);
  await assert.rejects(() => reconcileGitHubOwnedWorkspaces(root, { retentionMs: 31 * 24 * hour }), /retention/);
  await assert.rejects(() => reconcileGitHubOwnedWorkspaces(root, { maxDeletes: 0 }), /maxDeletes/);
});

test("ownership markers contain no repository, commit, or credential identity", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-workspace-marker-"));
  const workspace = join(root, "synsec-github-marker");
  await mkdir(workspace);
  const marker = await markGitHubWorkspaceOwned(workspace, () => now);
  assert.match(marker.workspaceId, /^[a-f0-9]{32}$/);
  const raw = await readFile(join(workspace, ".synsec-workspace.json"), "utf8");
  for (const forbidden of ["repository", "commit", "token", "installation", "github.com"]) {
    assert.equal(raw.includes(forbidden), false);
  }
});
