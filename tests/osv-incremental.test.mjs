import assert from "node:assert/strict";
import { mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { buildOsvArguments, scannerSupportsNativeChangedFiles } from "../packages/scanners/dist/index.js";

async function repository() {
  const root = await mkdtemp(join(tmpdir(), "synsec-osv-incremental-"));
  await mkdir(join(root, "apps", "web"), { recursive: true });
  await mkdir(join(root, "services", "api"), { recursive: true });
  await writeFile(join(root, "apps", "web", "package-lock.json"), "{}\n");
  await writeFile(join(root, "services", "api", "requirements-dev.txt"), "flask==3.0.0\n");
  return root;
}

test("OSV-Scanner is advertised as a native changed-file scanner", () => {
  assert.equal(scannerSupportsNativeChangedFiles("osv-scanner"), true);
});

test("OSV-Scanner defaults to recursive repository scanning", async () => {
  const root = await repository();
  assert.deepEqual(buildOsvArguments({ target: { path: root } }), [
    "scan", "--format", "json", "source", "-r", root,
  ]);
});

test("OSV-Scanner narrows a dependency-only changed scope to explicit lockfiles", async () => {
  const root = await repository();
  assert.deepEqual(buildOsvArguments({
    target: { path: root },
    changedFiles: [
      "apps/web/package-lock.json",
      "services/api/requirements-dev.txt",
      "apps/web/package-lock.json",
    ],
  }), [
    "scan",
    "--format",
    "json",
    "source",
    `--lockfile=${join(root, "apps", "web", "package-lock.json")}`,
    `--lockfile=${join(root, "services", "api", "requirements-dev.txt")}`,
  ]);
});

test("OSV-Scanner falls back to full repository coverage for mixed or ambiguous changes", async () => {
  const root = await repository();
  for (const changedFiles of [
    ["apps/web/package-lock.json", "apps/web/src/index.ts"],
    ["apps/web/package.json"],
    ["osv-scanner.toml"],
    ["missing/package-lock.json"],
    ["../outside/package-lock.json"],
    ["/tmp/package-lock.json"],
  ]) {
    assert.deepEqual(buildOsvArguments({ target: { path: root }, changedFiles }), [
      "scan", "--format", "json", "source", "-r", root,
    ]);
  }
});

test("OSV-Scanner does not use a changed lockfile symlink as a native scan target", async () => {
  const root = await repository();
  const outside = join(await mkdtemp(join(tmpdir(), "synsec-osv-outside-")), "package-lock.json");
  await writeFile(outside, "{}\n");
  const linkedDir = join(root, "linked");
  await mkdir(linkedDir, { recursive: true });
  await symlink(outside, join(linkedDir, "package-lock.json"));

  assert.deepEqual(buildOsvArguments({
    target: { path: root },
    changedFiles: ["linked/package-lock.json"],
  }), ["scan", "--format", "json", "source", "-r", root]);
});

test("OSV-Scanner bounds native dependency scope", async () => {
  const root = await repository();
  const changedFiles = [];
  for (let index = 0; index < 101; index += 1) {
    const rel = `deps/${index}/package-lock.json`;
    const dir = join(root, "deps", String(index));
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "package-lock.json"), "{}\n");
    changedFiles.push(rel);
  }
  assert.deepEqual(buildOsvArguments({ target: { path: root }, changedFiles }), [
    "scan", "--format", "json", "source", "-r", root,
  ]);
});
