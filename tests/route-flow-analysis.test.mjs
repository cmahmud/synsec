import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
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
    assert.equal(analysis.importCallLinks.linkedCallCount, 0);
    assert.equal(analysis.routeFlows[0]?.callScope, "same-file");
    assert.deepEqual(analysis.routeFlows[0]?.evidence, []);
  } finally {
    await repo.cleanup();
  }
});
