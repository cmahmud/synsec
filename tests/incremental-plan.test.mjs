import assert from "node:assert/strict";
import test from "node:test";

import { buildIncrementalScanPlan } from "@synsec/repository/incremental-plan";

function graph() {
  return {
    schemaVersion: 1,
    nodes: ["src/a.ts", "src/b.ts", "src/c.ts", "src/d.ts"],
    edges: [
      { from: "src/b.ts", specifier: "./a", kind: "import", line: 1, target: "src/a.ts", resolution: "repository-file" },
      { from: "src/c.ts", specifier: "./b", kind: "import", line: 1, target: "src/b.ts", resolution: "repository-file" },
      { from: "src/d.ts", specifier: "pkg", kind: "import", line: 1, resolution: "external-or-unresolved" },
    ],
    resolvedEdgeCount: 2,
    unresolvedEdgeCount: 1,
  };
}

test("incremental planner selects direct changes plus bounded local dependents", () => {
  const plan = buildIncrementalScanPlan(graph(), ["src/a.ts"], { maxDependentDepth: 2, maxDependents: 10 });
  assert.equal(plan.mode, "targeted");
  assert.equal(plan.reason, "targeted-with-bounded-dependents");
  assert.deepEqual(plan.changedFiles, ["src/a.ts"]);
  assert.deepEqual(plan.selectedFiles, ["src/a.ts", "src/b.ts", "src/c.ts"]);
  assert.deepEqual(plan.dependentFiles, [
    { path: "src/b.ts", depth: 1, triggeredBy: "src/a.ts" },
    { path: "src/c.ts", depth: 2, triggeredBy: "src/a.ts" },
  ]);
  assert.equal(plan.interpretation, "coverage-heuristic-not-proof-of-unaffected-code");
});

test("incremental planner falls back to full scan for high-impact repository configuration", () => {
  for (const changed of [
    ".github/workflows/ci.yml",
    "package-lock.json",
    "infra/main.tf",
    "tsconfig.json",
    "config/security.yaml",
    "synsec.config.json",
  ]) {
    const plan = buildIncrementalScanPlan(graph(), [changed]);
    assert.equal(plan.mode, "full-repository", changed);
    assert.equal(plan.reason, "high-impact-file-changed", changed);
    assert.deepEqual(plan.selectedFiles, []);
  }
});

test("incremental planner fails closed when a changed analyzable source file is missing from the graph", () => {
  const plan = buildIncrementalScanPlan(graph(), ["src/not-indexed.ts"]);
  assert.equal(plan.mode, "full-repository");
  assert.equal(plan.reason, "changed-source-not-indexed");
});

test("incremental planner fails closed when dependent expansion exceeds its bound", () => {
  const plan = buildIncrementalScanPlan(graph(), ["src/a.ts"], { maxDependentDepth: 3, maxDependents: 1 });
  assert.equal(plan.mode, "full-repository");
  assert.equal(plan.reason, "dependent-expansion-exceeded-bound");
});

test("incremental planner rejects unsafe paths and bounds configuration", () => {
  assert.equal(buildIncrementalScanPlan(graph(), ["../outside.ts"]).reason, "invalid-changed-path");
  assert.equal(buildIncrementalScanPlan(graph(), ["/absolute.ts"]).reason, "invalid-changed-path");
  assert.throws(() => buildIncrementalScanPlan(graph(), ["src/a.ts"], { maxDependentDepth: 11 }), /maxDependentDepth/);
  assert.throws(() => buildIncrementalScanPlan(graph(), ["src/a.ts"], { maxDependents: 0 }), /maxDependents/);
});

test("incremental planner handles no-op changes without manufacturing scope", () => {
  const plan = buildIncrementalScanPlan(graph(), []);
  assert.equal(plan.mode, "targeted");
  assert.equal(plan.reason, "no-changes");
  assert.deepEqual(plan.selectedFiles, []);
});
