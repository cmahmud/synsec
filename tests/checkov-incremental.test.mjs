import assert from "node:assert/strict";
import test from "node:test";
import { buildCheckovArguments } from "../packages/scanners/dist/index.js";

const context = {
  target: { path: "/repo" },
};

test("Checkov defaults to repository directory scanning without changed-file scope", () => {
  assert.deepEqual(buildCheckovArguments(context), [
    "-d",
    "/repo",
    "-o",
    "json",
    "--quiet",
    "--compact",
  ]);
});

test("Checkov uses repeated file arguments for bounded changed-file scope", () => {
  assert.deepEqual(buildCheckovArguments({
    ...context,
    changedFiles: ["infra/main.tf", "deploy/app.yaml", "infra/main.tf"],
  }), [
    "-o",
    "json",
    "--quiet",
    "--compact",
    "-f",
    "infra/main.tf",
    "-f",
    "deploy/app.yaml",
  ]);
});

test("Checkov changed-file execution independently rejects path escape and absolute paths", () => {
  for (const path of ["../outside.tf", "infra/../../outside.tf", "/tmp/outside.tf", "C:/outside.tf"]) {
    assert.throws(() => buildCheckovArguments({ ...context, changedFiles: [path] }), /unsafe repository path/);
  }
});

test("Checkov changed-file execution bounds adapter scope and treats an empty list as full scan", () => {
  assert.equal(buildCheckovArguments({ ...context, changedFiles: [] })[0], "-d");
  assert.throws(() => buildCheckovArguments({
    ...context,
    changedFiles: Array.from({ length: 501 }, (_, index) => `infra/file-${index}.tf`),
  }), /500-file adapter limit/);
});
