import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildRepositoryIndex } from "../packages/repository/dist/analysis.js";
import { buildModuleGraph, findModuleNeighborhood } from "../packages/repository/dist/module-graph.js";

test("module graph resolves local JavaScript and TypeScript imports without confusing packages for repository files", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-module-graph-"));
  try {
    await mkdir(join(root, "src", "db"), { recursive: true });
    const app = `import express from "express";\nimport { requireAuth } from "./auth.js";\nimport { loadUser } from "./db/index.js";\nexport async function handler() { return loadUser(); }\n`;
    const auth = `export function requireAuth() { return true; }\n`;
    const db = `import { requireAuth } from "../auth.js";\nexport function loadUser() { requireAuth(); return {}; }\n`;
    await writeFile(join(root, "src", "app.ts"), app);
    await writeFile(join(root, "src", "auth.ts"), auth);
    await writeFile(join(root, "src", "db", "index.ts"), db);

    const files = [
      { path: "src/app.ts", size: Buffer.byteLength(app) },
      { path: "src/auth.ts", size: Buffer.byteLength(auth) },
      { path: "src/db/index.ts", size: Buffer.byteLength(db) },
    ];
    const index = await buildRepositoryIndex(root, files);
    const graph = buildModuleGraph(index, files);

    assert.equal(graph.schemaVersion, 1);
    assert.deepEqual(graph.nodes, ["src/app.ts", "src/auth.ts", "src/db/index.ts"]);
    assert.equal(graph.resolvedEdgeCount, 3);
    assert.equal(graph.unresolvedEdgeCount, 1);
    assert.ok(graph.edges.some((edge) => edge.specifier === "./auth.js" && edge.target === "src/auth.ts"));
    assert.ok(graph.edges.some((edge) => edge.specifier === "./db/index.js" && edge.target === "src/db/index.ts"));
    assert.ok(graph.edges.some((edge) => edge.specifier === "express" && edge.resolution === "external-or-unresolved" && edge.target === undefined));

    const neighborhood = findModuleNeighborhood(graph, "./src/app.ts", 3);
    assert.equal(neighborhood.interpretation, "module-import-reachability-only");
    assert.deepEqual(neighborhood.dependencies, [
      { path: "src/auth.ts", depth: 1 },
      { path: "src/db/index.ts", depth: 1 },
    ]);

    const authNeighborhood = findModuleNeighborhood(graph, "src/auth.ts", 3);
    assert.deepEqual(authNeighborhood.dependents, [
      { path: "src/app.ts", depth: 1 },
      { path: "src/db/index.ts", depth: 1 },
    ]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("module graph resolves explicit relative Python package imports and bounds traversal", () => {
  const files = [
    { path: "service/__init__.py", size: 1 },
    { path: "service/api.py", size: 1 },
    { path: "service/auth.py", size: 1 },
  ];
  const index = {
    schemaVersion: 1,
    generatedAt: new Date(0).toISOString(),
    indexedFileCount: files.length,
    moduleEdges: [
      { from: "service/api.py", specifier: ".auth", kind: "python-import", line: 1 },
      { from: "service/auth.py", specifier: ".", kind: "python-import", line: 1 },
    ],
    routes: [],
    authSignals: [],
    sinks: [],
  };

  const graph = buildModuleGraph(index, files);
  assert.ok(graph.edges.some((edge) => edge.specifier === ".auth" && edge.target === "service/auth.py"));
  assert.ok(graph.edges.some((edge) => edge.specifier === "." && edge.target === "service/__init__.py"));
  assert.deepEqual(findModuleNeighborhood(graph, "service/api.py", 0).dependencies, []);
});
