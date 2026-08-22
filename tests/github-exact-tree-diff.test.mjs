import assert from "node:assert/strict";
import test from "node:test";
import { deriveExactChangedFiles } from "@synsec/github/exact-tree-diff";

function tree(entries) {
  return entries.map(({ mode = "100644", type = "blob", object, path }) => `${mode} ${type} ${object}\t${path}\0`).join("");
}

const a = "a".repeat(40);
const b = "b".repeat(40);
const c = "c".repeat(40);

function runner(outputs) {
  let call = 0;
  return async (_command, args) => {
    assert.equal(args.includes("ls-tree"), true);
    const stdout = outputs[call++];
    return { exitCode: 0, stdout, stderr: "" };
  };
}

test("exact tree diff returns only head paths whose blobs changed", async () => {
  const base = tree([
    { object: a, path: "src/a.ts" },
    { object: b, path: "src/b.ts" },
  ]);
  const head = tree([
    { object: c, path: "src/a.ts" },
    { object: b, path: "src/b.ts" },
    { object: a, path: "src/new.ts" },
  ]);
  const plan = await deriveExactChangedFiles("/base", "/head", { run: runner([base, head]) });
  assert.equal(plan.mode, "changed-files");
  assert.equal(plan.reason, "exact-tree-diff");
  assert.deepEqual(plan.changedFiles, ["src/a.ts", "src/new.ts"]);
  assert.deepEqual(plan.deletedFiles, []);
});

test("exact tree diff falls back to full scan when a path was deleted", async () => {
  const base = tree([{ object: a, path: "src/deleted.ts" }]);
  const head = tree([]);
  const plan = await deriveExactChangedFiles("/base", "/head", { run: runner([base, head]) });
  assert.equal(plan.mode, "full-repository");
  assert.equal(plan.reason, "deletion-requires-full-scan");
  assert.deepEqual(plan.deletedFiles, ["src/deleted.ts"]);
  assert.deepEqual(plan.changedFiles, []);
});

test("exact tree diff falls back on changed non-blob entries", async () => {
  const base = tree([{ object: a, path: "vendor/submodule" }]);
  const head = tree([{ mode: "160000", type: "commit", object: b, path: "vendor/submodule" }]);
  const plan = await deriveExactChangedFiles("/base", "/head", { run: runner([base, head]) });
  assert.equal(plan.mode, "full-repository");
  assert.equal(plan.reason, "unsupported-tree-change");
});

test("exact tree diff refuses malformed or unsafe tree paths", async () => {
  const malformed = `100644 blob ${a}\t../escape.ts\0`;
  const plan = await deriveExactChangedFiles("/base", "/head", { run: runner([malformed, malformed]) });
  assert.equal(plan.mode, "full-repository");
  assert.equal(plan.reason, "tree-read-failed");
});

test("exact tree diff falls back when the changed set exceeds its bound", async () => {
  const base = tree([]);
  const head = tree([
    { object: a, path: "src/a.ts" },
    { object: b, path: "src/b.ts" },
  ]);
  const plan = await deriveExactChangedFiles("/base", "/head", {
    run: runner([base, head]),
    maxChangedFiles: 1,
  });
  assert.equal(plan.mode, "full-repository");
  assert.equal(plan.reason, "too-many-changed-files");
});
