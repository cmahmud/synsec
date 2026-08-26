import assert from "node:assert/strict";
import test from "node:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { findExternalDependencyUsage } from "@synsec/repository/dependency-usage";
import { buildModuleGraph } from "@synsec/repository/module-graph";

test("dependency usage excludes Python imports proven to be repository-local", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-dependency-usage-local-"));
  try {
    await mkdir(join(root, "service"), { recursive: true });
    const init = "";
    const local = "def load():\n    return {}\n";
    const app = "from service.db import load\nimport requests\n\ndef main():\n    return load()\n";
    await writeFile(join(root, "service", "__init__.py"), init);
    await writeFile(join(root, "service", "db.py"), local);
    await writeFile(join(root, "service", "app.py"), app);

    const files = [
      { path: "service/__init__.py", size: Buffer.byteLength(init) },
      { path: "service/db.py", size: Buffer.byteLength(local) },
      { path: "service/app.py", size: Buffer.byteLength(app) },
    ];
    const index = await buildRepositoryIndex(root, files);
    const graph = buildModuleGraph(index, files);

    assert.deepEqual(findExternalDependencyUsage(index, graph, "service"), {
      packageName: "service",
      status: "unknown",
      evidence: [],
      excludedRepositoryLocalImportCount: 1,
      interpretation: "observed-import-evidence-not-runtime-reachability",
    });
    const requests = findExternalDependencyUsage(index, graph, "requests");
    assert.equal(requests.status, "observed-import");
    assert.equal(requests.evidence.length, 1);
    assert.equal(requests.evidence[0].specifier, "requests");
    assert.equal(requests.excludedRepositoryLocalImportCount, 0);
    assert.equal(requests.interpretation, "observed-import-evidence-not-runtime-reachability");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("dependency usage keeps ambiguous imports as conservative external evidence", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-dependency-usage-ambiguous-"));
  try {
    await mkdir(join(root, "service", "db"), { recursive: true });
    const init = "";
    const db = "def load():\n    return {}\n";
    const app = "from service.db import load\n";
    await writeFile(join(root, "service", "__init__.py"), init);
    await writeFile(join(root, "service", "db.py"), db);
    await writeFile(join(root, "service", "db", "__init__.py"), db);
    await writeFile(join(root, "service", "app.py"), app);

    const files = [
      { path: "service/__init__.py", size: Buffer.byteLength(init) },
      { path: "service/db.py", size: Buffer.byteLength(db) },
      { path: "service/db/__init__.py", size: Buffer.byteLength(db) },
      { path: "service/app.py", size: Buffer.byteLength(app) },
    ];
    const index = await buildRepositoryIndex(root, files);
    const graph = buildModuleGraph(index, files);
    const usage = findExternalDependencyUsage(index, graph, "service");

    assert.equal(graph.resolvedEdgeCount, 0);
    assert.equal(usage.status, "observed-import");
    assert.equal(usage.evidence[0].specifier, "service.db");
    assert.equal(usage.excludedRepositoryLocalImportCount, 0);
    assert.equal(usage.interpretation, "observed-import-evidence-not-runtime-reachability");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("dependency usage bounds evidence and tolerates invalid evidence limits", () => {
  const index = {
    schemaVersion: 1,
    generatedAt: new Date(0).toISOString(),
    indexedFileCount: 1,
    moduleEdges: Array.from({ length: 150 }, (_, line) => ({
      from: "src/app.ts",
      specifier: "lodash/fp",
      kind: "import",
      line: line + 1,
    })),
    routes: [],
    authSignals: [],
    sinks: [],
  };
  const graph = {
    schemaVersion: 1,
    nodes: ["src/app.ts"],
    edges: index.moduleEdges.map((edge) => ({ ...edge, resolution: "external-or-unresolved" })),
    resolvedEdgeCount: 0,
    unresolvedEdgeCount: 150,
  };

  assert.equal(findExternalDependencyUsage(index, graph, "lodash", 1000).evidence.length, 100);
  assert.equal(findExternalDependencyUsage(index, graph, "lodash", Number.NaN).evidence.length, 10);
});
