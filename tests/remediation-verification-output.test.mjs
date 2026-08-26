import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { writeRemediationVerification } from "@synsec/lifecycle";

const verification = {
  schemaVersion: 1,
  generatedAt: "2026-08-22T21:30:00.000Z",
  beforeReportId: "before",
  afterReportId: "after",
  items: [{
    fingerprint: "finding-1",
    title: "Sensitive finding title",
    status: "inconclusive",
    reasons: ["The detecting scanner did not rerun."],
  }],
  newFindings: [],
  summary: { fixed: 0, persisting: 0, inconclusive: 1, missingBaseline: 0, newFindings: 0 },
};

test("remediation verification output is private, atomic-shaped, and repairs permissive overwrite modes", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-verification-output-"));
  const path = join(root, "verification.json");
  try {
    await writeFile(path, "old\n", { encoding: "utf8", mode: 0o644 });
    if (process.platform !== "win32") await chmod(path, 0o644);

    await writeRemediationVerification(path, verification);
    assert.deepEqual(JSON.parse(await readFile(path, "utf8")), verification);
    if (process.platform !== "win32") assert.equal((await stat(path)).mode & 0o777, 0o600);

    const leftovers = (await readdir(root)).filter((name) => name.includes(".tmp"));
    assert.deepEqual(leftovers, []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
