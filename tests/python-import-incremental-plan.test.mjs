import assert from "node:assert/strict";
import test from "node:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildIncrementalScanPlan } from "@synsec/repository/incremental-plan";
import { buildModuleGraph } from "@synsec/repository/module-graph";

test("incremental planning expands through conservative absolute Python package imports", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-python-incremental-"));
  try {
    await mkdir(join(root, "service"), { recursive: true });
    const packageInit = "";
    const db = "def load_user():\n    return {}\n";
    const api = "from service.db import load_user\n\ndef handle():\n    return load_user()\n";
    const app = "from service.api import handle\n\ndef main():\n    return handle()\n";
    await writeFile(join(root, "service", "__init__.py"), packageInit);
    await writeFile(join(root, "service", "db.py"), db);
    await writeFile(join(root, "service", "api.py"), api);
    await writeFile(join(root, "service", "app.py"), app);

    const files = [
      { path: "service/__init__.py", size: Buffer.byteLength(packageInit) },
      { path: "service/db.py", size: Buffer.byteLength(db) },
      { path: "service/api.py", size: Buffer.byteLength(api) },
      { path: "service/app.py", size: Buffer.byteLength(app) },
    ];
    const index = await buildRepositoryIndex(root, files);
    const graph = buildModuleGraph(index, files);
    const plan = buildIncrementalScanPlan(graph, ["service/db.py"], {
      maxDependentDepth: 2,
      maxDependents: 10,
    });

    assert.equal(plan.mode, "targeted");
    assert.equal(plan.reason, "targeted-with-bounded-dependents");
    assert.deepEqual(plan.selectedFiles, [
      "service/api.py",
      "service/app.py",
      "service/db.py",
    ]);
    assert.deepEqual(plan.dependentFiles, [
      { path: "service/api.py", depth: 1, triggeredBy: "service/db.py" },
      { path: "service/app.py", depth: 2, triggeredBy: "service/db.py" },
    ]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("incremental planning does not expand through ambiguous Python import shapes", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-python-ambiguous-"));
  try {
    await mkdir(join(root, "service", "db"), { recursive: true });
    const packageInit = "";
    const dbModule = "def load_user():\n    return {}\n";
    const dbPackage = "def load_user():\n    return {}\n";
    const api = "from service.db import load_user\n\ndef handle():\n    return load_user()\n";
    await writeFile(join(root, "service", "__init__.py"), packageInit);
    await writeFile(join(root, "service", "db.py"), dbModule);
    await writeFile(join(root, "service", "db", "__init__.py"), dbPackage);
    await writeFile(join(root, "service", "api.py"), api);

    const files = [
      { path: "service/__init__.py", size: Buffer.byteLength(packageInit) },
      { path: "service/db.py", size: Buffer.byteLength(dbModule) },
      { path: "service/db/__init__.py", size: Buffer.byteLength(dbPackage) },
      { path: "service/api.py", size: Buffer.byteLength(api) },
    ];
    const index = await buildRepositoryIndex(root, files);
    const graph = buildModuleGraph(index, files);
    const plan = buildIncrementalScanPlan(graph, ["service/db.py"], {
      maxDependentDepth: 2,
      maxDependents: 10,
    });

    assert.equal(graph.resolvedEdgeCount, 0);
    assert.equal(plan.mode, "targeted");
    assert.deepEqual(plan.selectedFiles, ["service/db.py"]);
    assert.deepEqual(plan.dependentFiles, []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
