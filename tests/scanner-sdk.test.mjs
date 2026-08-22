import test from "node:test";
import assert from "node:assert/strict";
import { runProcess } from "../packages/scanner-sdk/dist/index.js";

test("runProcess captures bounded stdout and stderr", async () => {
  const result = await runProcess(process.execPath, [
    "-e",
    "process.stdout.write('hello'); process.stderr.write('note');",
  ], { maxOutputBytes: 1024 });
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "hello");
  assert.equal(result.stderr, "note");
});

test("runProcess rejects scanner output that exceeds its memory bound", async () => {
  await assert.rejects(
    runProcess(process.execPath, [
      "-e",
      "process.stdout.write('x'.repeat(4096)); setTimeout(() => {}, 1000);",
    ], { maxOutputBytes: 128, timeoutMs: 5_000 }),
    /exceeded the 128 byte stdout limit/,
  );
});

test("runProcess surfaces timeouts instead of returning an ambiguous exit code", async () => {
  await assert.rejects(
    runProcess(process.execPath, ["-e", "setTimeout(() => {}, 5000);"], { timeoutMs: 50 }),
    /timed out after 50 ms/,
  );
});
