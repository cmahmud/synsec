import test from "node:test";
import assert from "node:assert/strict";
import { delimiter, resolve } from "node:path";
import { buildScannerProcessEnv, runProcess, sanitizeScannerSearchPath } from "../packages/scanner-sdk/dist/index.js";

test("buildScannerProcessEnv preserves execution variables but drops credentials, proxy URLs, and config roots", () => {
  const systemBin = resolve("synsec-test-system-bin");
  const env = buildScannerProcessEnv({
    PATH: systemBin,
    HOME: "/tmp/home",
    USERPROFILE: "C:\\Users\\scanner",
    APPDATA: "C:\\Users\\scanner\\AppData\\Roaming",
    LOCALAPPDATA: "C:\\Users\\scanner\\AppData\\Local",
    XDG_CONFIG_HOME: "/tmp/config",
    XDG_CACHE_HOME: "/tmp/cache",
    LANG: "en_US.UTF-8",
    LC_CTYPE: "en_US.UTF-8",
    GITHUB_TOKEN: "secret-github-token",
    NPM_TOKEN: "secret-registry-token",
    AWS_SECRET_ACCESS_KEY: "secret-cloud-key",
    HTTPS_PROXY: "http://user:password@proxy.invalid",
  });

  assert.equal(env.PATH, systemBin);
  assert.equal(env.LANG, "en_US.UTF-8");
  assert.equal(env.LC_CTYPE, "en_US.UTF-8");
  assert.equal(env.XDG_CACHE_HOME, "/tmp/cache");
  assert.equal(env.HOME, undefined);
  assert.equal(env.USERPROFILE, undefined);
  assert.equal(env.APPDATA, undefined);
  assert.equal(env.LOCALAPPDATA, undefined);
  assert.equal(env.XDG_CONFIG_HOME, undefined);
  assert.equal(env.GITHUB_TOKEN, undefined);
  assert.equal(env.NPM_TOKEN, undefined);
  assert.equal(env.AWS_SECRET_ACCESS_KEY, undefined);
  assert.equal(env.HTTPS_PROXY, undefined);
});

test("sanitizeScannerSearchPath drops relative and repository-controlled command lookup entries", () => {
  const worktree = resolve("synsec-test-worktree");
  const repositoryBin = resolve(worktree, "node_modules", ".bin");
  const outsideBin = resolve("synsec-test-system-bin");
  const rawPath = [".", "relative-tools", repositoryBin, outsideBin, outsideBin, ""].join(delimiter);

  assert.equal(sanitizeScannerSearchPath(rawPath, worktree), outsideBin);
});

test("buildScannerProcessEnv applies scanner working-tree PATH isolation", () => {
  const worktree = resolve("synsec-test-worktree");
  const repositoryBin = resolve(worktree, "tools");
  const outsideBin = resolve("synsec-test-system-bin");
  const env = buildScannerProcessEnv({ PATH: [repositoryBin, outsideBin].join(delimiter) }, worktree);

  assert.equal(env.PATH, outsideBin);
});

test("runProcess rejects relative executable paths before spawning", async () => {
  await assert.rejects(
    runProcess("./repository-controlled-scanner", [], { cwd: resolve("synsec-test-worktree") }),
    /Relative scanner executable paths are not allowed/,
  );
  await assert.rejects(
    runProcess("tools/repository-controlled-scanner", []),
    /Relative scanner executable paths are not allowed/,
  );
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

test("runProcess does not implicitly expose parent user configuration roots", async () => {
  const previousHome = process.env.HOME;
  const previousConfig = process.env.XDG_CONFIG_HOME;
  process.env.HOME = "/tmp/synsec-sensitive-home";
  process.env.XDG_CONFIG_HOME = "/tmp/synsec-sensitive-config";
  try {
    const result = await runProcess(process.execPath, [
      "-e",
      "process.stdout.write(JSON.stringify({home:process.env.HOME,config:process.env.XDG_CONFIG_HOME}));",
    ]);
    assert.deepEqual(JSON.parse(result.stdout), {});
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    if (previousConfig === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = previousConfig;
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
