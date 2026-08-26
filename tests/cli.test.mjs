import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createServer } from "node:http";
import { promisify } from "node:util";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildReport } from "../packages/report/dist/index.js";

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

test("CLI help documents finding lifecycle, remediation verification, and multi-model review", async () => {
  const { stdout } = await exec(process.execPath, [cli.pathname, "help"]);
  assert.match(stdout, /synsec triage <report\.json>/);
  assert.match(stdout, /synsec verify <before\.json> <after\.json>/);
  assert.match(stdout, /false-positive/);
  assert.match(stdout, /accepted-risk/);
  assert.match(stdout, /--ai-models <a,b,c>/);
  assert.match(stdout, /--ai-min-reviewers <n>/);
  assert.match(stdout, /model inference only/);
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

test("CLI verify confirms a remediation only when the detecting scanner reran over repository scope", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-verify-test-"));
  try {
    const scan = {
      scanner: "fixture",
      startedAt: "2026-01-01T00:00:00.000Z",
      completedAt: "2026-01-01T00:00:01.000Z",
      target: { path: root },
      diagnostics: [],
      findings: [{
        id: "A",
        title: "Finding A",
        category: "sast",
        severity: "high",
        confidence: 1,
        scanner: { name: "fixture", ruleId: "A" },
        location: { path: "src/A.ts", startLine: 1 },
      }],
    };
    const before = buildReport({ target: { path: root }, scans: [scan], scope: { mode: "repository" } });
    const after = buildReport({
      target: { path: root },
      scans: [{ ...scan, findings: [] }],
      scope: { mode: "repository" },
    });
    const beforePath = join(root, "before.json");
    const afterPath = join(root, "after.json");
    const outputPath = join(root, "verification.json");
    await writeFile(beforePath, JSON.stringify(before), "utf8");
    await writeFile(afterPath, JSON.stringify(after), "utf8");

    const result = await exec(process.execPath, [
      cli.pathname,
      "verify",
      beforePath,
      afterPath,
      "--output",
      outputPath,
    ]);
    assert.match(result.stdout, /1 fixed/);
    assert.match(result.stdout, /\[FIXED\] Finding A/);
    const verification = JSON.parse(await readFile(outputPath, "utf8"));
    assert.equal(verification.summary.fixed, 1);
    assert.equal(verification.summary.inconclusive, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("CLI review can run bounded multi-model consensus without treating it as scanner evidence", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-cli-consensus-"));
  const requestedModels = [];
  const server = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    requestedModels.push(body.model);
    const verdict = body.model === "reviewer-c" ? "likely" : "confirmed";
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({
      choices: [{
        message: {
          content: JSON.stringify({
            verdict,
            confidence: 0.9,
            severity: "high",
            summary: `Reviewed by ${body.model}`,
            rationale: "Repository-local defensive review fixture.",
            gate: [],
            remediation: "Use a safer repository-local implementation.",
          }),
        },
      }],
    }));
  });
  await new Promise((resolvePromise) => server.listen(0, "127.0.0.1", resolvePromise));
  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const report = buildReport({
      target: { path: root },
      scans: [{
        scanner: "fixture",
        startedAt: "2026-08-22T20:00:00.000Z",
        completedAt: "2026-08-22T20:00:01.000Z",
        target: { path: root },
        diagnostics: [],
        findings: [{
          id: "fixture-finding",
          title: "Review fixture",
          category: "sast",
          severity: "high",
          confidence: 0.95,
          scanner: { name: "fixture", ruleId: "FIX-REVIEW" },
          location: { path: "src/app.ts", startLine: 3 },
        }],
      }],
      scope: { mode: "repository" },
    });
    const reportPath = join(root, "report.json");
    const outputPath = join(root, "consensus.json");
    await writeFile(reportPath, JSON.stringify(report), "utf8");

    const result = await exec(process.execPath, [
      cli.pathname,
      "review",
      reportPath,
      "--root",
      root,
      "--ai-base-url",
      `http://127.0.0.1:${address.port}`,
      "--ai-models",
      "reviewer-a,reviewer-b,reviewer-c",
      "--ai-min-reviewers",
      "2",
      "--ai-review-concurrency",
      "2",
      "--output",
      outputPath,
    ]);
    assert.match(result.stdout, /AI consensus review/);
    assert.deepEqual([...requestedModels].sort(), ["reviewer-a", "reviewer-b", "reviewer-c"]);

    const output = JSON.parse(await readFile(outputPath, "utf8"));
    assert.equal(output.schemaVersion, 2);
    assert.equal(output.reviewMode, "consensus");
    assert.equal(output.interpretation, "model-consensus-not-scanner-evidence");
    assert.deepEqual(output.models, ["reviewer-a", "reviewer-b", "reviewer-c"]);
    const entry = output.reviews[report.findings[0].fingerprint];
    assert.equal(entry.reviews.length, 3);
    assert.equal(entry.failures.length, 0);
    assert.equal(entry.consensus.verdict, "confirmed");
    assert.equal(entry.consensus.agreement, "majority");
    assert.equal(entry.consensus.interpretation, "model-consensus-not-scanner-evidence");
  } finally {
    await new Promise((resolvePromise, reject) => server.close((error) => error ? reject(error) : resolvePromise()));
    await rm(root, { recursive: true, force: true });
  }
});
