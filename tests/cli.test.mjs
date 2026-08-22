import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const exec = promisify(execFile);
const cli = new URL("../apps/cli/dist/index.js", import.meta.url);

test("CLI reports its version", async () => {
  const { stdout } = await exec(process.execPath, [cli.pathname, "version"]);
  assert.equal(stdout.trim(), "0.2.0");
});

test("CLI lists capability-scoped defensive workflows", async () => {
  const { stdout } = await exec(process.execPath, [cli.pathname, "workflows"]);
  assert.match(stdout, /repository-review/);
  assert.match(stdout, /dependency-review/);
  assert.match(stdout, /secrets-review/);
  assert.match(stdout, /external network assessment: forbidden/);
});

test("CLI help documents finding lifecycle triage", async () => {
  const { stdout } = await exec(process.execPath, [cli.pathname, "help"]);
  assert.match(stdout, /synsec triage <report\.json>/);
  assert.match(stdout, /false-positive/);
  assert.match(stdout, /accepted-risk/);
});

test("CLI init writes a safe default configuration", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-cli-test-"));
  try {
    await exec(process.execPath, [cli.pathname, "init", root]);
    const parsed = JSON.parse(await readFile(join(root, "synsec.config.json"), "utf8"));
    assert.equal(parsed.schemaVersion, 1);
    assert.equal(parsed.ai.enabled, false);
    assert.equal(parsed.ai.sendSourceContext, false);
    assert.ok(parsed.scanners.includes("opengrep"));
    assert.ok(parsed.scanners.includes("syft"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("CLI imports SARIF into a native SynSec report", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-sarif-test-"));
  try {
    const input = join(root, "external.sarif");
    const output = join(root, "imported.json");
    await writeFile(input, JSON.stringify({
      version: "2.1.0",
      runs: [{
        tool: { driver: { name: "FixtureScanner", rules: [{ id: "FIX-1", shortDescription: { text: "Fixture issue" } }] } },
        results: [{ ruleId: "FIX-1", level: "warning", message: { text: "Fixture issue" } }],
      }],
    }), "utf8");

    const { stdout } = await exec(process.execPath, [
      cli.pathname,
      "import-sarif",
      input,
      "--root",
      root,
      "--output",
      output,
    ]);
    assert.match(stdout, /Imported 1 SARIF finding/);
    const report = JSON.parse(await readFile(output, "utf8"));
    assert.equal(report.findingCount, 1);
    assert.equal(report.findings[0].primary.scanner.name, "FixtureScanner");
    assert.equal(report.findings[0].primary.severity, "medium");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("CLI triage persists explicit lifecycle decisions and lists them", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-triage-test-"));
  try {
    const input = join(root, "external.sarif");
    const reportPath = join(root, "report.json");
    const storePath = join(root, "lifecycle.json");
    await writeFile(input, JSON.stringify({
      version: "2.1.0",
      runs: [{
        tool: { driver: { name: "FixtureScanner", rules: [{ id: "FIX-2", shortDescription: { text: "Review me" } }] } },
        results: [{ ruleId: "FIX-2", level: "error", message: { text: "Review me" } }],
      }],
    }), "utf8");

    await exec(process.execPath, [
      cli.pathname,
      "import-sarif",
      input,
      "--root",
      root,
      "--output",
      reportPath,
    ]);
    const report = JSON.parse(await readFile(reportPath, "utf8"));
    const fingerprint = report.findings[0].fingerprint;

    const updated = await exec(process.execPath, [
      cli.pathname,
      "triage",
      reportPath,
      fingerprint,
      "confirmed",
      "--note",
      "reviewed",
      "--store",
      storePath,
    ]);
    assert.match(updated.stdout, /-> confirmed/);

    const stored = JSON.parse(await readFile(storePath, "utf8"));
    assert.equal(stored.records[fingerprint].state, "confirmed");
    assert.equal(stored.records[fingerprint].note, "reviewed");

    const listed = await exec(process.execPath, [
      cli.pathname,
      "triage",
      reportPath,
      "--list",
      "--store",
      storePath,
    ]);
    assert.match(listed.stdout, /confirmed/);
    assert.match(listed.stdout, /Review me/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
