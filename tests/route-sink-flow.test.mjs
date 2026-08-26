import assert from "node:assert/strict";
import test from "node:test";
import {
  findingRouteSinkFlowEvidence,
  routeSinkFlowContext,
} from "@synsec/repository/route-sink-flow";

const route = {
  path: "server.ts",
  line: 5,
  method: "GET",
  route: "/users",
  frameworkHint: "Node HTTP router",
  handler: "listUsers",
};

const handler = {
  id: "server.ts:listUsers:20",
  path: "server.ts",
  name: "listUsers",
  line: 20,
  endLine: 24,
  kind: "function",
};

const helper = {
  id: "server.ts:loadUsers:30",
  path: "server.ts",
  name: "loadUsers",
  line: 30,
  endLine: 35,
  kind: "function",
};

const graph = {
  schemaVersion: 1,
  nodes: [handler, helper],
  edges: [{ from: handler.id, callee: "loadUsers", line: 22, target: helper.id, resolution: "same-file-function" }],
  resolvedEdgeCount: 1,
  unresolvedEdgeCount: 0,
  skippedFiles: [],
  interpretation: "lexical-call-evidence-only",
};

const entrypoint = {
  route,
  resolution: "named-function",
  handler,
  calls: {
    root: handler.id,
    maxDepth: 3,
    callees: [{ id: helper.id, depth: 1 }],
    callers: [],
    interpretation: "lexical-call-evidence-only",
  },
  interpretation: "structural-route-call-evidence-only",
};

function flowFixture() {
  const index = {
    schemaVersion: 1,
    generatedAt: "2026-08-22T21:00:00.000Z",
    indexedFileCount: 1,
    moduleEdges: [],
    routes: [route],
    authSignals: [],
    sinks: [
      { path: "server.ts", line: 23, kind: "network", evidence: "fetch(secretUrl)" },
      { path: "server.ts", line: 33, kind: "database", evidence: "db.query(sql)" },
      { path: "server.ts", line: 80, kind: "process", evidence: "exec(command)" },
    ],
  };
  return routeSinkFlowContext(index, entrypoint, graph);
}

test("resolved route flow links sinks inside the handler and bounded callees without source text", () => {
  const context = flowFixture();
  assert.equal(context.interpretation, "structural-route-call-sink-evidence-only");
  assert.equal(context.callScope, "same-file");
  assert.deepEqual(context.kinds, ["network", "database"]);
  assert.deepEqual(context.evidence.map((item) => [item.functionName, item.depth, item.kind]), [
    ["listUsers", 0, "network"],
    ["loadUsers", 1, "database"],
  ]);
  assert.equal(JSON.stringify(context).includes("secretUrl"), false);
  assert.equal(JSON.stringify(context).includes("db.query"), false);
  assert.equal(JSON.stringify(context).includes("exec(command)"), false);
});

test("exact finding route-flow evidence matches only the linked sink line and stays sanitized", () => {
  const context = flowFixture();
  const direct = findingRouteSinkFlowEvidence([context], "./server.ts", 23);
  assert.deepEqual(direct, [{
    method: "GET",
    route: "/users",
    frameworkHint: "Node HTTP router",
    resolution: "named-function",
    handler: "listUsers",
    sinkKind: "network",
    functionName: "listUsers",
    depth: 0,
    callScope: "same-file",
    interpretation: "structural-route-call-sink-evidence-only",
  }]);
  assert.deepEqual(findingRouteSinkFlowEvidence([context], "server.ts", 24), []);
  assert.equal(JSON.stringify(direct).includes("secretUrl"), false);
});

test("explicit imported call links can extend route flow to a sink in another local module", () => {
  const imported = {
    id: "service.ts:loadUsers:10",
    path: "service.ts",
    name: "loadUsers",
    line: 10,
    endLine: 14,
    kind: "function",
  };
  const crossModuleGraph = {
    ...graph,
    nodes: [handler, imported],
    edges: [{ from: handler.id, callee: "service.loadUsers", line: 22, resolution: "external-or-unresolved" }],
    resolvedEdgeCount: 0,
    unresolvedEdgeCount: 1,
  };
  const crossModuleEntrypoint = {
    ...entrypoint,
    calls: { ...entrypoint.calls, callees: [] },
  };
  const index = {
    schemaVersion: 1,
    generatedAt: "2026-08-23T16:00:00.000Z",
    indexedFileCount: 2,
    moduleEdges: [],
    routes: [route],
    authSignals: [],
    sinks: [{ path: "service.ts", line: 12, kind: "database", evidence: "db.query(secretSql)" }],
  };
  const importCallLinks = {
    schemaVersion: 1,
    links: [{
      from: handler.id,
      line: 22,
      callee: "service.loadUsers",
      target: imported.id,
      targetPath: "service.ts",
      importedName: "loadUsers",
      bindingKind: "javascript-namespace-import",
      evidence: "explicit-import-binding-to-unique-local-function",
    }],
    linkedCallCount: 1,
    interpretation: "cross-module-import-call-evidence-only",
  };

  const context = routeSinkFlowContext(index, crossModuleEntrypoint, crossModuleGraph, { importCallLinks });
  assert.equal(context.callScope, "same-file-and-explicit-imports");
  assert.deepEqual(context.evidence.map((item) => [item.path, item.functionName, item.depth, item.kind]), [
    ["service.ts", "loadUsers", 1, "database"],
  ]);
  const findingEvidence = findingRouteSinkFlowEvidence([context], "service.ts", 12);
  assert.equal(findingEvidence[0]?.callScope, "same-file-and-explicit-imports");
  assert.equal(JSON.stringify(findingEvidence).includes("secretSql"), false);
});

test("unresolved routes and ambiguous function ownership do not manufacture sink flow", () => {
  const index = {
    schemaVersion: 1,
    generatedAt: "2026-08-22T21:00:00.000Z",
    indexedFileCount: 1,
    moduleEdges: [],
    routes: [route],
    authSignals: [],
    sinks: [{ path: "server.ts", line: 23, kind: "network", evidence: "fetch(url)" }],
  };
  assert.equal(routeSinkFlowContext(index, { route, resolution: "unresolved", interpretation: "structural-route-call-evidence-only" }, graph), undefined);

  const overlapping = {
    ...graph,
    nodes: [
      ...graph.nodes,
      { id: "server.ts:nested:22", path: "server.ts", name: "nested", line: 22, endLine: 24, kind: "function" },
    ],
  };
  const ambiguousEntrypoint = {
    ...entrypoint,
    calls: {
      ...entrypoint.calls,
      callees: [...entrypoint.calls.callees, { id: "server.ts:nested:22", depth: 1 }],
    },
  };
  const context = routeSinkFlowContext(index, ambiguousEntrypoint, overlapping);
  assert.deepEqual(context.evidence, []);
});
