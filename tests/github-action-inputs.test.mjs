import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  booleanInput,
  changedOnlyInput,
  resolveWorkspaceFileInput,
} from "../apps/github-action/dist/inputs.js";

test("GitHub Action boolean inputs accept documented values and reject ambiguity", () => {
  assert.equal(booleanInput(undefined, true), true);
  assert.equal(booleanInput(" yes ", false), true);
  assert.equal(booleanInput("0", true), false);
  assert.throws(() => booleanInput("maybe", false), /Expected a boolean action input/);

  assert.equal(changedOnlyInput("auto"), undefined);
  assert.equal(changedOnlyInput("true"), true);
  assert.equal(changedOnlyInput("no"), false);
  assert.throws(() => changedOnlyInput("sometimes"), /changed-only must be auto, true, or false/);
});

test("GitHub Action file inputs resolve regular files inside the checkout", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-action-input-"));
  await mkdir(join(root, "config"));
  await writeFile(join(root, "config", "synsec.json"), "{}", "utf8");

  const resolved = await resolveWorkspaceFileInput(root, "config/synsec.json", "config-path");
  assert.equal(resolved, join(root, "config", "synsec.json"));
});

test("GitHub Action file inputs reject lexical traversal outside the checkout", async () => {
  const parent = await mkdtemp(join(tmpdir(), "synsec-action-parent-"));
  const root = join(parent, "repo");
  await mkdir(root);
  await writeFile(join(parent, "outside.json"), "{}", "utf8");

  await assert.rejects(
    resolveWorkspaceFileInput(root, "../outside.json", "baseline-path"),
    /must resolve inside GITHUB_WORKSPACE/,
  );
});

test("GitHub Action file inputs reject symlinks that escape the checkout", async () => {
  const parent = await mkdtemp(join(tmpdir(), "synsec-action-symlink-"));
  const root = join(parent, "repo");
  await mkdir(root);
  const outside = join(parent, "outside.json");
  await writeFile(outside, "{}", "utf8");
  await symlink(outside, join(root, "baseline.json"));

  await assert.rejects(
    resolveWorkspaceFileInput(root, "baseline.json", "baseline-path"),
    /existing file inside GITHUB_WORKSPACE/,
  );
});

test("GitHub Action file inputs reject directories", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-action-dir-"));
  await mkdir(join(root, "config"));

  await assert.rejects(
    resolveWorkspaceFileInput(root, "config", "config-path"),
    /regular file inside GITHUB_WORKSPACE/,
  );
});
