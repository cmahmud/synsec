import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BetterleaksAdapter, OpengrepAdapter } from "@synsec/scanners";

async function writeExecutable(directory, name, body) {
  const path = join(directory, name);
  await writeFile(path, `#!/bin/sh\n${body}\n`, "utf8");
  await chmod(path, 0o700);
}

test("scanner availability sanitizes version stdout and failure diagnostics", async () => {
  const directory = await mkdtemp(join(tmpdir(), "synsec-scanner-availability-"));
  const originalPath = process.env.PATH;
  try {
    await writeExecutable(
      directory,
      "opengrep",
      `printf '%s\\n' 'opengrep 1.2.3 api_key="version secret value"'`,
    );
    await writeExecutable(
      directory,
      "betterleaks",
      `printf '%s\\n' "password='failure secret value'" >&2\nexit 2`,
    );
    process.env.PATH = originalPath ? `${directory}:${originalPath}` : directory;

    const available = await new OpengrepAdapter().checkAvailability();
    assert.equal(available.available, true);
    assert.equal(available.version?.includes("version secret value"), false);
    assert.match(available.version ?? "", /api_key=\[REDACTED\]/);

    const unavailable = await new BetterleaksAdapter().checkAvailability();
    assert.equal(unavailable.available, false);
    assert.equal(unavailable.reason?.includes("failure secret value"), false);
    assert.match(unavailable.reason ?? "", /password=\[REDACTED\]/);
  } finally {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
    await rm(directory, { recursive: true, force: true });
  }
});
