import assert from "node:assert/strict";
import test from "node:test";
import { CheckovAdapter, buildCheckovArguments } from "../packages/scanners/dist/index.js";

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

test("Checkov uses one injected runner for availability and scan execution", async () => {
  const calls = [];
  const runner = async (command, args, options = {}) => {
    calls.push({ command, args, options });
    if (args[0] === "--version") {
      return { exitCode: 0, stdout: "Checkov 3.2.0\n", stderr: "", signal: null, timedOut: false, truncated: false };
    }
    return {
      exitCode: 1,
      stdout: JSON.stringify({ check_type: "terraform", results: { failed_checks: [] } }),
      stderr: "",
      signal: null,
      timedOut: false,
      truncated: false,
    };
  };
  const adapter = new CheckovAdapter(runner);

  assert.deepEqual(await adapter.checkAvailability(), { available: true, version: "Checkov 3.2.0" });
  const result = await adapter.scan({ ...context, changedFiles: ["infra/main.tf"] });
  assert.equal(result.scanner, "checkov");
  assert.deepEqual(result.findings, []);
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0].args, ["--version"]);
  assert.deepEqual(calls[1].args, ["-o", "json", "--quiet", "--compact", "-f", "infra/main.tf"]);
  assert.equal(calls[1].options.cwd, "/repo");
});
