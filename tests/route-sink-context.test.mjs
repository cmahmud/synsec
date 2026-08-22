import test from "node:test";
import assert from "node:assert/strict";

import { repositoryRouteSinkContexts, routeSinkContext } from "../packages/repository/dist/route-sink-context.js";

function index() {
  return {
    schemaVersion: 1,
    generatedAt: "2026-08-22T15:10:00.000Z",
    indexedFileCount: 1,
    moduleEdges: [],
    routes: [
      { path: "src/routes.ts", line: 20, method: "POST", route: "/jobs" },
      { path: "src/routes.ts", line: 100, method: "GET", route: "/users" },
      { path: "src/routes.ts", line: 220, method: "GET", route: "/health" },
    ],
    authSignals: [],
    sinks: [
      { path: "./src\\routes.ts", line: 24, kind: "process", evidence: "spawn(command)" },
      { path: "src/routes.ts", line: 28, kind: "filesystem", evidence: "writeFile(path, data)" },
      { path: "src/routes.ts", line: 104, kind: "database", evidence: "query(sql)" },
      { path: "src/routes.ts", line: 400, kind: "network", evidence: "fetch(url)" },
    ],
  };
}

test("routeSinkContext records bounded same-file sink proximity", () => {
  const data = index();
  const context = routeSinkContext(data, data.routes[0]);
  assert.equal(context.interpretation, "lexical-sink-signals-only");
  assert.deepEqual(context.kinds, ["process", "filesystem"]);
  assert.deepEqual(context.evidence, [
    { line: 24, distance: 4, kind: "process" },
    { line: 28, distance: 8, kind: "filesystem" },
  ]);
});

test("routeSinkContext does not infer a sink when none is nearby", () => {
  const data = index();
  const context = routeSinkContext(data, data.routes[2], { radius: 20 });
  assert.deepEqual(context.kinds, []);
  assert.deepEqual(context.evidence, []);
});

test("sink evidence is ordered by proximity before sink kind", () => {
  const data = index();
  data.sinks.push({ path: "src/routes.ts", line: 102, kind: "network", evidence: "fetch(url)" });
  const context = routeSinkContext(data, data.routes[1]);
  assert.deepEqual(context.evidence.slice(0, 2), [
    { line: 102, distance: 2, kind: "network" },
    { line: 104, distance: 4, kind: "database" },
  ]);
});

test("repositoryRouteSinkContexts bounds route output", () => {
  const contexts = repositoryRouteSinkContexts(index(), { maxRoutes: 2 });
  assert.equal(contexts.length, 2);
  assert.deepEqual(contexts.map((item) => item.route.route), ["/jobs", "/users"]);
});
