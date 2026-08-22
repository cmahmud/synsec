import test from "node:test";
import assert from "node:assert/strict";
import { buildScannerProcessEnv, runProcess } from "../packages/scanner-sdk/dist/index.js";

test("buildScannerProcessEnv preserves execution variables but drops credentials and proxy URLs", () => {
  const env = buildScannerProcessEnv({
    PATH: "/usr/bin",
    HOME: "/tmp/home",
    LANG: "en_US.UTF-8",
    LC_CTYPE: "en_US.UTF-8",
    GITHUB_TOKEN: "secret-github-token",
    NPM_TOKEN: "secret-registry-token",
    AWS_SECRET_ACCESS_KEY: "secret-cloud-key",
    HTTPS_PROXY: "http://user:password@proxy.invalid",
  });

  assert.equal(env.PATH, "/usr/bin");
  assert.equal(env.HOME, "/tmp/home");
  assert.equal(env.LANG, "en_US.UTF-8");
  assert.equal(env.LC_CTYPE, "en_US.UTF-8");
  assert.equal(env.GITHUB_TOKEN, undefined);
  assert.equal(env.NPM_TOKEN, undefined);
  assert.equal(env.AWS_SECRET_ACCESS_KEY, undefined);
  assert.equal(env.HTTPS_PROXY, undefined);
});

test("runProcess does not implicitly pass parent credentials to scanners", async () => {
  const previous = process.env.SYNSEC_TEST_SECRET;
  process.env.SYNSEC_TEST_SECRET = "should-not-reach-scanner";
  try {
    const result = await runProcess(process.execPath, [
      "-e",
      "process.stdout.write(process.env.SYNSEC_TEST_SECRET || 'missing');",
    ]);
    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout, "missing");
  } finally {
    if (previous === undefined) delete process.env.SYNSEC_TEST_SECRET;
    else process.env.SYNSEC_TEST_SECRET = previous;
  }
});

test("runProcess accepts an explicit child environment when a scanner genuinely needs one", async () => {
  const result = await runProcess(process.execPath, [
    "-e",
    "process.stdout.write(process.env.SYNSEC_EXPLICIT || 'missing');",
  ], { env: { ...buildScannerProcessEnv(), SYNSEC_EXPLICIT: "allowed-by-caller" } });
  assert.equal(result.stdout, "allowed-by-caller");
});

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

test("runProcess rejects invalid timeout configuration before spawning", async () => {
  await assert.rejects(
    runProcess(process.execPath, ["-e", "process.exit(0)"], { timeoutMs: 0 }),
    /timeoutMs must be a positive finite number/,
  );
  await assert.rejects(
    runProcess(process.execPath, ["-e", "process.exit(0)"], { timeoutMs: Number.NaN }),
    /timeoutMs must be a positive finite number/,
  );
});
