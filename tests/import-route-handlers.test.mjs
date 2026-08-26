import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function makeRepository(filesByPath) {
  const root = await mkdtemp(join(tmpdir(), "synsec-imported-route-handler-"));
  const files = [];
  for (const [path, content] of Object.entries(filesByPath)) {
    const absolute = join(root, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, content, "utf8");
    files.push({ path, size: Buffer.byteLength(content) });
  }
  return { root, files, cleanup: () => rm(root, { recursive: true, force: true }) };
}

async function analyze(repo) {
  const index = await buildRepositoryIndex(repo.root, repo.files);
  const moduleGraph = buildModuleGraph(index, repo.files);
  return await buildRepositoryRouteFlowAnalysis(repo.root, repo.files, index, moduleGraph);
}

test("Node routes resolve an explicit repository-local named import handler", async () => {
  const repo = await makeRepository({
    "server.ts": [
      'import { listUsers as handleUsers } from "./handlers.js";',
      'router.get("/users", handleUsers);',
    ].join("\n"),
    "handlers.ts": [
      "export function listUsers() {",
      "  db.query(sqlText);",
      "}",
    ].join("\n"),
  });

  try {
    const analysis = await analyze(repo);
    assert.equal(analysis.entrypoints[0]?.resolution, "imported-named-function");
    assert.equal(analysis.entrypoints[0]?.handler?.path, "handlers.ts");
    assert.equal(analysis.entrypoints[0]?.handler?.name, "listUsers");
    assert.deepEqual(analysis.routeFlows[0]?.evidence.map(({ path, line, kind, depth }) => ({ path, line, kind, depth })), [
      { path: "handlers.ts", line: 2, kind: "database", depth: 0 },
    ]);
    assert.equal(JSON.stringify(analysis.routeFlows).includes("sqlText"), false);
    assert.equal(JSON.stringify(analysis.routeFlows).includes("db.query"), false);
  } finally {
    await repo.cleanup();
  }
});

test("Node routes resolve an explicitly exported destructured require handler", async () => {
  const repo = await makeRepository({
    "server.cjs": [
      'const { listUsers: handleUsers } = require("./handlers.cjs");',
      'router.get("/users", handleUsers);',
    ].join("\n"),
    "handlers.cjs": [
      "function listUsers() {",
      "  db.query(sqlText);",
      "}",
      "exports.listUsers = listUsers;",
    ].join("\n"),
  });

  try {
    const analysis = await analyze(repo);
    assert.equal(analysis.entrypoints[0]?.resolution, "imported-named-function");
    assert.equal(analysis.entrypoints[0]?.handler?.path, "handlers.cjs");
  } finally {
    await repo.cleanup();
  }
});

test("same-named local target functions without export evidence remain unresolved", async () => {
  const repo = await makeRepository({
    "server.ts": [
      'import { listUsers as handleUsers } from "./handlers.js";',
      'router.get("/users", handleUsers);',
    ].join("\n"),
    "handlers.ts": [
      "function listUsers() {",
      "  db.query(sqlText);",
      "}",
    ].join("\n"),
  });

  try {
    const analysis = await analyze(repo);
    assert.equal(analysis.entrypoints[0]?.resolution, "unresolved");
    assert.deepEqual(analysis.routeFlows, []);
  } finally {
    await repo.cleanup();
  }
});

test("shadowed imported route handlers remain unresolved", async () => {
  const repo = await makeRepository({
    "server.ts": [
      'import { listUsers as handleUsers } from "./handlers.js";',
      "const handleUsers = localFactory();",
      'router.get("/users", handleUsers);',
    ].join("\n"),
    "handlers.ts": "export function listUsers() { db.query(sqlText); }\n",
  });

  try {
    const analysis = await analyze(repo);
    assert.equal(analysis.entrypoints[0]?.resolution, "unresolved");
    assert.deepEqual(analysis.routeFlows, []);
  } finally {
    await repo.cleanup();
  }
});

test("ambiguous imported handler targets remain unresolved", async () => {
  const repo = await makeRepository({
    "server.ts": [
      'import { listUsers as handleUsers } from "./handlers.js";',
      'import { listUsers as handleUsers } from "./other.js";',
      'router.get("/users", handleUsers);',
    ].join("\n"),
    "handlers.ts": "export function listUsers() { db.query(sqlText); }\n",
    "other.ts": "export function listUsers() { db.query(otherSql); }\n",
  });

  try {
    const analysis = await analyze(repo);
    assert.equal(analysis.entrypoints[0]?.resolution, "unresolved");
    assert.deepEqual(analysis.routeFlows, []);
  } finally {
    await repo.cleanup();
  }
});
