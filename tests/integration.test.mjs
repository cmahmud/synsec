import test from "node:test";
import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { delimiter, join } from "node:path";
import { tmpdir } from "node:os";
import { defaultConfig } from "../packages/config/dist/index.js";
import { runScanEngine } from "../packages/engine/dist/index.js";

test("scan engine runs an available adapter end-to-end and builds a correlated report", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-integration-repo-"));
  const bin = await mkdtemp(join(tmpdir(), "synsec-integration-bin-"));
  const originalPath = process.env.PATH ?? "";

  try {
    await mkdir(join(root, "src"));
    await writeFile(join(root, "package.json"), JSON.stringify({ name: "fixture", version: "1.0.0" }));
    await writeFile(join(root, "src", "index.js"), `import express from "express";
const app = express();
app.get("/health", (_req, res) => res.json({ ok: true }));
`);

    const trivy = join(bin, "trivy");
    await writeFile(trivy, `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "Version: 99.0.0-fixture"
  exit 0
fi
cat <<'JSON'
{"Results":[{"Target":"package-lock.json","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-4242","PkgName":"express","InstalledVersion":"1.0.0","FixedVersion":"1.0.1","Title":"Fixture dependency vulnerability","Severity":"HIGH"}]}]}
JSON
`);
    await chmod(trivy, 0o755);
    process.env.PATH = `${bin}${delimiter}${originalPath}`;

    const config = structuredClone(defaultConfig);
    config.scanners = ["trivy"];
    config.parallelism = 1;

    const outcome = await runScanEngine({ rootPath: root, config, toolVersion: "test" });
    assert.equal(outcome.report.scanners.length, 1);
    assert.equal(outcome.report.scanners[0].scanner, "trivy");
    assert.equal(outcome.report.rawFindingCount, 1);
    assert.equal(outcome.report.findingCount, 1);
    assert.equal(outcome.report.summary.high, 1);
    assert.equal(outcome.report.scope.mode, "repository");
    assert.equal(outcome.failures.length, 0);
    assert.equal(outcome.report.repository.languages.JavaScript, 1);
    assert.equal(outcome.repositoryIndex.indexedFileCount, 1);
    assert.ok(outcome.repositoryIndex.moduleEdges.some((edge) => edge.specifier === "express"));
    assert.ok(outcome.repositoryIndex.routes.some((route) => route.route === "/health"));
    const usage = outcome.report.findings[0].primary.metadata.dependencyUsage;
    assert.equal(usage.status, "observed-import");
    assert.equal(usage.packageName, "express");
    assert.equal(usage.evidence[0].specifier, "express");
  } finally {
    process.env.PATH = originalPath;
    await rm(root, { recursive: true, force: true });
    await rm(bin, { recursive: true, force: true });
  }
});

test("scan engine adds bounded proximity signals to located non-secret findings", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-context-repo-"));
  const bin = await mkdtemp(join(tmpdir(), "synsec-context-bin-"));
  const originalPath = process.env.PATH ?? "";

  try {
    await mkdir(join(root, "src"));
    await writeFile(join(root, "src", "app.js"), `import express from "express";
const app = express();
function requireAuth(req, res, next) { return next(); }
app.get("/users/:id", requireAuth, async (req, res) => {
  const rows = await db.query("select * from users where id = $1", [req.params.id]);
  res.json(rows);
});
`);

    const opengrep = join(bin, "opengrep");
    await writeFile(opengrep, `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "opengrep 99.0.0-fixture"
  exit 0
fi
cat <<'JSON'
{"results":[{"check_id":"fixture.sql","path":"src/app.js","start":{"line":5,"col":3},"end":{"line":5,"col":40},"extra":{"message":"Fixture query finding","severity":"ERROR","metadata":{"cwe":["CWE-89"]}}}]}
JSON
`);
    await chmod(opengrep, 0o755);
    process.env.PATH = `${bin}${delimiter}${originalPath}`;

    const config = structuredClone(defaultConfig);
    config.scanners = ["opengrep"];
    config.parallelism = 1;
    const outcome = await runScanEngine({ rootPath: root, config, toolVersion: "test" });
    const context = outcome.report.findings[0].primary.metadata.repositoryContext;
    assert.equal(context.interpretation, "proximity-signals-only");
    assert.ok(context.nearbyRoutes.some((signal) => signal.route === "/users/:id"));
    assert.ok(context.nearbyAuthSignals.some((signal) => signal.kind === "authentication"));
    assert.ok(context.nearbySinks.some((signal) => signal.kind === "database"));
    assert.equal("evidence" in context.nearbySinks[0], false);
  } finally {
    process.env.PATH = originalPath;
    await rm(root, { recursive: true, force: true });
    await rm(bin, { recursive: true, force: true });
  }
});

test("scan engine enriches exact sink findings across an explicit local import", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-cross-module-engine-"));
  const bin = await mkdtemp(join(tmpdir(), "synsec-cross-module-bin-"));
  const originalPath = process.env.PATH ?? "";

  try {
    await writeFile(join(root, "server.ts"), [
      'import { runQuery } from "./service.js";',
      "export function listUsers() {",
      "  runQuery();",
      "}",
      'router.get("/users", listUsers);',
    ].join("\n"));
    await writeFile(join(root, "service.ts"), [
      "export function runQuery() {",
      "  db.query(secretSql);",
      "}",
    ].join("\n"));

    const opengrep = join(bin, "opengrep");
    await writeFile(opengrep, `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "opengrep 99.0.0-fixture"
  exit 0
fi
cat <<'JSON'
{"results":[{"check_id":"fixture.cross-module","path":"service.ts","start":{"line":2,"col":3},"end":{"line":2,"col":22},"extra":{"message":"Fixture imported sink","severity":"ERROR","metadata":{"cwe":["CWE-89"]}}}]}
JSON
`);
    await chmod(opengrep, 0o755);
    process.env.PATH = `${bin}${delimiter}${originalPath}`;

    const config = structuredClone(defaultConfig);
    config.scanners = ["opengrep"];
    config.parallelism = 1;
    const outcome = await runScanEngine({ rootPath: root, config, toolVersion: "test" });
    const primary = outcome.report.findings[0].primary;
    const routeFlow = primary.metadata.routeFlow;

    assert.equal(routeFlow.length, 1);
    assert.equal(routeFlow[0].callScope, "same-file-and-explicit-imports");
    assert.equal(routeFlow[0].interpretation, "structural-route-call-sink-evidence-only");
    assert.deepEqual(
      routeFlow[0].evidence.map(({ path, line, kind, functionName, depth }) => ({ path, line, kind, functionName, depth })),
      [{ path: "service.ts", line: 2, kind: "database", functionName: "runQuery", depth: 1 }],
    );
    assert.equal(JSON.stringify(routeFlow).includes("secretSql"), false);
    assert.equal(JSON.stringify(routeFlow).includes("db.query"), false);
  } finally {
    process.env.PATH = originalPath;
    await rm(root, { recursive: true, force: true });
    await rm(bin, { recursive: true, force: true });
  }
});
