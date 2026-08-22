import test from "node:test";
import assert from "node:assert/strict";

import { repositoryRouteAuthContexts, routeAuthContext } from "../packages/repository/dist/route-auth-context.js";

function index() {
  return {
    schemaVersion: 1,
    generatedAt: "2026-08-22T15:00:00.000Z",
    indexedFileCount: 1,
    moduleEdges: [],
    routes: [
      { path: "src/routes.ts", line: 20, method: "GET", route: "/account", frameworkHint: "Node HTTP router" },
      { path: "src/routes.ts", line: 90, method: "POST", route: "/admin", frameworkHint: "Node HTTP router" },
      { path: "src/routes.ts", line: 180, method: "GET", route: "/health", frameworkHint: "Node HTTP router" },
    ],
    authSignals: [
      { path: "./src\\routes.ts", line: 15, kind: "authentication", evidence: "requireAuth" },
      { path: "src/routes.ts", line: 84, kind: "authentication", evidence: "requireAuth" },
      { path: "src/routes.ts", line: 88, kind: "authorization", evidence: "isAdmin" },
      { path: "src/routes.ts", line: 300, kind: "token", evidence: "verifyToken" },
    ],
    sinks: [],
  };
}

test("routeAuthContext reports nearby authentication without claiming protection", () => {
  const data = index();
  const context = routeAuthContext(data, data.routes[0]);
  assert.equal(context.status, "authentication-signal-observed");
  assert.equal(context.interpretation, "lexical-auth-signals-only");
  assert.deepEqual(context.evidence, [{ line: 15, distance: 5, kind: "authentication" }]);
});

test("authorization evidence takes precedence over nearby authentication", () => {
  const data = index();
  const context = routeAuthContext(data, data.routes[1]);
  assert.equal(context.status, "authorization-signal-observed");
  assert.equal(context.evidence[0].kind, "authorization");
  assert.equal(context.evidence[0].distance, 2);
});

test("routes without nearby auth evidence stay explicitly unknown rather than public", () => {
  const data = index();
  const context = routeAuthContext(data, data.routes[2], { radius: 20 });
  assert.equal(context.status, "no-auth-signal-observed");
  assert.deepEqual(context.evidence, []);
});

test("repositoryRouteAuthContexts bounds route output", () => {
  const contexts = repositoryRouteAuthContexts(index(), { maxRoutes: 2 });
  assert.equal(contexts.length, 2);
  assert.deepEqual(contexts.map((item) => item.route.route), ["/account", "/admin"]);
});
