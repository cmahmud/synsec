import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function makeRepository(filesByPath) {
  const root = await mkdtemp(join(tmpdir(), "synsec-route-flow-analysis-"));
  const files = [];
  for (const [path, content] of Object.entries(filesByPath)) {
    const absolute = join(root, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, content, "utf8");
    files.push({ path, size: Buffer.byteLength(content) });
  }
  return { root, files, cleanup: () => rm(root, { recursive: true, force: true }) };
}

test("composed route analysis reaches an exact sink through one explicit local import", async () => {
  const repo = await makeRepository({
    "server.ts": [
      'import { runQuery } from "./service.js";',
      "export function listUsers() {",
      "  runQuery();",
      "}",
      'router.get("/users", listUsers);',
    ].join("\n"),
    "service.ts": [
      "export function runQuery() {",
      "  db.query(secretSql);",
      "}",
    ].join("\n"),
  });

  try {
    const index = await buildRepositoryIndex(repo.root, repo.files);
    const moduleGraph = buildModuleGraph(index, repo.files);
    const analysis = await buildRepositoryRouteFlowAnalysis(repo.root, repo.files, index, moduleGraph);

    assert.equal(analysis.interpretation, "repository-structural-route-flow-evidence-only");
    assert.equal(analysis.inputFileCount, 2);
    assert.equal(analysis.analyzedFileCount, 2);
    assert.equal(analysis.skippedUnsafeFileCount, 0);
    assert.equal(analysis.truncatedFileCount, 0);
    assert.equal(analysis.coverage, "complete-input");
    assert.equal(analysis.importCallLinks.linkedCallCount, 1);
    assert.equal(analysis.routeFlows.length, 1);
    const flow = analysis.routeFlows[0];
    assert.equal(flow?.callScope, "same-file-and-explicit-imports");
    assert.deepEqual(flow?.evidence.map(({ path, line, kind, functionName, depth }) => ({
      path, line, kind, functionName, depth,
    })), [{
      path: "service.ts",
      line: 2,
      kind: "database",
      functionName: "runQuery",
      depth: 1,
    }]);
    assert.equal(JSON.stringify(flow).includes("secretSql"), false);
    assert.equal(JSON.stringify(flow).includes("db.query"), false);
  } finally {
    await repo.cleanup();
  }
});

test("composed route analysis remains same-file when the import is external or unresolved", async () => {
  const repo = await makeRepository({
    "server.ts": [
      'import { runQuery } from "database-client";',
      "export function listUsers() {",
      "  runQuery();",
      "}",
      'router.get("/users", listUsers);',
    ].join("\n"),
  });

  try {
    const index = await buildRepositoryIndex(repo.root, repo.files);
    const moduleGraph = buildModuleGraph(index, repo.files);
    const analysis = await buildRepositoryRouteFlowAnalysis(repo.root, repo.files, index, moduleGraph);
    assert.equal(analysis.inputFileCount, 1);
    assert.equal(analysis.analyzedFileCount, 1);
    assert.equal(analysis.skippedUnsafeFileCount, 0);
    assert.equal(analysis.truncatedFileCount, 0);
    assert.equal(analysis.coverage, "complete-input");
    assert.equal(analysis.importCallLinks.linkedCallCount, 0);
    assert.equal(analysis.routeFlows[0]?.callScope, "same-file");
    assert.deepEqual(analysis.routeFlows[0]?.evidence, []);
  } finally {
    await repo.cleanup();
  }
});

test("composed route analysis refuses symlink source entries even when caller metadata includes them", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-route-flow-symlink-"));
  try {
    const target = [
      "export function linkedHandler() {",
      "  db.query(secretSql);",
      "}",
      'router.get("/linked", linkedHandler);',
    ].join("\n");
    await writeFile(join(root, "target.ts"), target, "utf8");
    await symlink("target.ts", join(root, "linked.ts"));

    const files = [{ path: "linked.ts", size: Buffer.byteLength(target) }];
    const index = await buildRepositoryIndex(root, files);
    const moduleGraph = buildModuleGraph(index, files);
    const analysis = await buildRepositoryRouteFlowAnalysis(root, files, index, moduleGraph);

    assert.equal(analysis.inputFileCount, 1);
    assert.equal(analysis.analyzedFileCount, 0);
    assert.equal(analysis.skippedUnsafeFileCount, 1);
    assert.equal(analysis.truncatedFileCount, 0);
    assert.equal(analysis.coverage, "complete-input");
    assert.equal(analysis.callGraph.nodes.length, 0);
    assert.equal(analysis.importCallLinks.linkedCallCount, 0);
    assert.deepEqual(analysis.routeFlows, []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("composed route analysis reports bounded input coverage instead of silently dropping files", async () => {
  const repo = await makeRepository({
    "a.ts": "export function a() {}\n",
    "b.ts": "export function b() {}\n",
    "c.ts": "export function c() {}\n",
  });

  try {
    const index = await buildRepositoryIndex(repo.root, repo.files);
    const moduleGraph = buildModuleGraph(index, repo.files);
    const analysis = await buildRepositoryRouteFlowAnalysis(repo.root, repo.files, index, moduleGraph, {
      maxFiles: 2,
    });

    assert.equal(analysis.inputFileCount, 3);
    assert.equal(analysis.analyzedFileCount, 2);
    assert.equal(analysis.skippedUnsafeFileCount, 0);
    assert.equal(analysis.truncatedFileCount, 1);
    assert.equal(analysis.coverage, "bounded-input");
    assert.deepEqual(analysis.callGraph.nodes.map((node) => node.path).sort(), ["a.ts", "b.ts"]);
  } finally {
    await repo.cleanup();
  }
});

test("composed route analysis rejects invalid file bounds", async () => {
  const repo = await makeRepository({ "server.ts": "export function handler() {}\n" });
  try {
    const index = await buildRepositoryIndex(repo.root, repo.files);
    const moduleGraph = buildModuleGraph(index, repo.files);
    await assert.rejects(
      buildRepositoryRouteFlowAnalysis(repo.root, repo.files, index, moduleGraph, { maxFiles: 0 }),
      /maxFiles must be an integer between 1 and 5000/,
    );
    await assert.rejects(
      buildRepositoryRouteFlowAnalysis(repo.root, repo.files, index, moduleGraph, { maxFiles: 5_001 }),
      /maxFiles must be an integer between 1 and 5000/,
    );
  } finally {
    await repo.cleanup();
  }
});
