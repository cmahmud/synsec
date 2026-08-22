import assert from "node:assert/strict";
import test from "node:test";
import { runProcess, sanitizeOperationalText } from "@synsec/scanner-sdk";

test("sanitizeOperationalText redacts common credential forms and bounds diagnostics", () => {
  const input = [
    "clone https://user:password@example.test/repo.git",
    "Authorization: Bearer abc.def.ghi",
    "api_key=super-secret-value",
    "password=\"super secret value\"",
    "auth_token='quoted secret value'",
    "fetch https://example.test/report?token=query-secret&format=json",
    "github_pat_abcdefghijklmnopqrstuvwxyz0123456789",
    "AKIAABCDEFGHIJKLMNOP",
    "eyJabcdefghijk.abcdefghijkl.abcdefghijkl",
  ].join("\n");

  const sanitized = sanitizeOperationalText(input, 4096);
  assert.equal(sanitized.includes("user:password"), false);
  assert.equal(sanitized.includes("super-secret-value"), false);
  assert.equal(sanitized.includes("super secret value"), false);
  assert.equal(sanitized.includes("quoted secret value"), false);
  assert.equal(sanitized.includes("query-secret"), false);
  assert.equal(sanitized.includes("github_pat_"), false);
  assert.equal(sanitized.includes("AKIAABCDEFGHIJKLMNOP"), false);
  assert.equal(sanitized.includes("eyJabcdefghijk"), false);
  assert.match(sanitized, /token=\[REDACTED\]&format=json/);
  assert.match(sanitized, /\[REDACTED/);

  const bounded = sanitizeOperationalText("x".repeat(100), 16);
  assert.equal(bounded.startsWith("x".repeat(16)), true);
  assert.match(bounded, /\[truncated\]$/);
});

test("runProcess preserves stdout evidence while redacting stderr diagnostics", async () => {
  const token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
  const output = await runProcess(
    process.execPath,
    ["-e", `process.stdout.write("finding-output"); process.stderr.write("token ${token}")`],
    { timeoutMs: 5_000 },
  );

  assert.equal(output.exitCode, 0);
  assert.equal(output.stdout, "finding-output");
  assert.equal(output.stderr.includes(token), false);
  assert.equal(output.stderr, "token [REDACTED_TOKEN]");
});

test("runProcess sanitizes spawn failures before rejecting", async () => {
  const secret = "spawn-secret-value";
  await assert.rejects(
    runProcess(`definitely-missing-scanner-api_key=${secret}`, [], { timeoutMs: 5_000 }),
    (error) => {
      assert.equal(error instanceof Error, true);
      assert.equal(error.message.includes(secret), false);
      assert.match(error.message, /api_key=\[REDACTED\]/);
      return true;
    },
  );
});

test("sanitizeOperationalText rejects invalid bounds", () => {
  assert.throws(() => sanitizeOperationalText("value", 0), /positive finite/);
  assert.throws(() => sanitizeOperationalText("value", Number.NaN), /positive finite/);
});
