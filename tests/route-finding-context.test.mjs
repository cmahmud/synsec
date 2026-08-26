import assert from "node:assert/strict";
import test from "node:test";
import { findingRepositoryContext } from "@synsec/repository/analysis";

test("finding repository context preserves only indexed named route-handler evidence", () => {
  const index = {
    schemaVersion: 1,
    generatedAt: "2026-08-22T21:00:00.000Z",
    indexedFileCount: 1,
    moduleEdges: [],
    routes: [
      {
        path: "server.ts",
        line: 10,
        method: "GET",
        route: "/users",
        frameworkHint: "Node HTTP router",
        handler: "listUsers",
      },
      {
        path: "server.ts",
        line: 20,
        method: "POST",
        route: "/users",
        frameworkHint: "Node HTTP router",
      },
    ],
    authSignals: [],
    sinks: [],
  };

  const context = findingRepositoryContext(index, "server.ts", 12, 20);
  assert.equal(context.interpretation, "proximity-signals-only");
  assert.deepEqual(context.nearbyRoutes[0], {
    line: 10,
    distance: 2,
    method: "GET",
    route: "/users",
    frameworkHint: "Node HTTP router",
    handler: "listUsers",
  });
  assert.equal(context.nearbyRoutes[1].handler, undefined);
});
