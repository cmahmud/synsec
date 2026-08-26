import test from "node:test";
import assert from "node:assert/strict";
import { asRecord, relativeLike } from "../packages/scanners/dist/utils.js";

test("scanner path normalization keeps repository-relative paths and strips the repository root", () => {
  assert.equal(relativeLike("/repo/src/app.ts", "/repo"), "src/app.ts");
  assert.equal(relativeLike("./src/app.ts", "/repo"), "src/app.ts");
  assert.equal(relativeLike("src\\app.ts", "C:\\repo"), "src/app.ts");
});

test("scanner path normalization rejects host paths and traversal outside the repository", () => {
  assert.equal(relativeLike("/etc/passwd", "/repo"), undefined);
  assert.equal(relativeLike("C:\\Windows\\system.ini", "C:\\repo"), undefined);
  assert.equal(relativeLike("../outside.txt", "/repo"), undefined);
  assert.equal(relativeLike("src/../../outside.txt", "/repo"), undefined);
});

test("asRecord does not treat arrays as object records", () => {
  assert.equal(asRecord([]), undefined);
  assert.deepEqual(asRecord({ ok: true }), { ok: true });
});
