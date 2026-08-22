import test from "node:test";
import assert from "node:assert/strict";

import { resolveRouteEntrypoints, routeEntrypointForLocation } from "../packages/repository/dist/route-entrypoints.js";

function emptyIndex(routes) {
  return {
    schemaVersion: 1,
    generatedAt: "2026-08-22T12:00:00.000Z",
    indexedFileCount: 1,
    moduleEdges: [],
    routes,
    authSignals: [],
    sinks: [],
  };
}

function graph() {
  return {
    schemaVersion: 1,
    nodes: [
      { id: "app.py:users:11", path: "app.py", name: "users", line: 11, endLine: 14, kind: "python-function" },
      { id: "app.py:load_user:20", path: "app.py", name: "load_user", line: 20, endLine: 22, kind: "python-function" },
      { id: "server.ts:listUsers:30", path: "server.ts", name: "listUsers", line: 30, endLine: 33, kind: "function" },
    ],
    edges: [
      { from: "app.py:users:11", callee: "load_user", line: 13, target: "app.py:load_user:20", resolution: "same-file-function" },
    ],
    resolvedEdgeCount: 1,
    unresolvedEdgeCount: 0,
    skippedFiles: [],
    interpretation: "lexical-call-evidence-only",
  };
}

test("decorated Python routes resolve to the nearest following function and bounded calls", () => {
  const index = emptyIndex([
    { path: "app.py", line: 10, method: "GET", route: "/users", frameworkHint: "Python web router" },
  ]);
  const [entrypoint] = resolveRouteEntrypoints(index, graph());
  assert.equal(entrypoint.resolution, "decorated-function");
  assert.equal(entrypoint.handler.id, "app.py:users:11");
  assert.equal(entrypoint.calls.callees[0].id, "app.py:load_user:20");
  assert.equal(entrypoint.interpretation, "structural-route-call-evidence-only");
});

test("generic Node router registrations remain unresolved instead of guessing a handler", () => {
  const index = emptyIndex([
    { path: "server.ts", line: 5, method: "GET", route: "/users", frameworkHint: "Node HTTP router" },
  ]);
  const [entrypoint] = resolveRouteEntrypoints(index, graph());
  assert.equal(entrypoint.resolution, "unresolved");
  assert.equal("handler" in entrypoint, false);
});

test("routeEntrypointForLocation only maps lines inside a resolved handler body", () => {
  const entrypoints = resolveRouteEntrypoints(
    emptyIndex([{ path: "app.py", line: 10, method: "GET", route: "/users", frameworkHint: "Python web router" }]),
    graph(),
  );
  assert.equal(routeEntrypointForLocation(entrypoints, "./app.py", 13)?.route.route, "/users");
  assert.equal(routeEntrypointForLocation(entrypoints, "app.py", 19), undefined);
});

test("decorator mapping refuses declarations beyond the configured distance", () => {
  const index = emptyIndex([
    { path: "app.py", line: 1, method: "GET", route: "/far", frameworkHint: "Python web router" },
  ]);
  const [entrypoint] = resolveRouteEntrypoints(index, graph(), { maxDeclarationDistance: 5 });
  assert.equal(entrypoint.resolution, "unresolved");
});
