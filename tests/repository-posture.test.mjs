import test from "node:test";
import assert from "node:assert/strict";

import { buildRepositoryPosture } from "../packages/repository/dist/posture.js";

function index() {
  return {
    schemaVersion: 1,
    generatedAt: "2026-08-22T15:20:00.000Z",
    indexedFileCount: 2,
    moduleEdges: [],
    routes: [
      { path: "src/routes.ts", line: 20, method: "GET", route: "/account" },
      { path: "src/routes.ts", line: 80, method: "POST", route: "/admin" },
      { path: "src/routes.ts", line: 160, method: "GET", route: "/health" },
    ],
    authSignals: [
      { path: "src/routes.ts", line: 16, kind: "authentication", evidence: "requireAuth" },
      { path: "src/routes.ts", line: 76, kind: "authorization", evidence: "isAdmin" },
    ],
    sinks: [
      { path: "src/routes.ts", line: 24, kind: "database", evidence: "query(sql)" },
      { path: "src/routes.ts", line: 84, kind: "process", evidence: "spawn(command)" },
      { path: "src/routes.ts", line: 88, kind: "database", evidence: "query(sql)" },
    ],
  };
}

test("buildRepositoryPosture aggregates lexical auth and sink route signals", () => {
  const posture = buildRepositoryPosture(index(), { authRadius: 20, sinkRadius: 20 });
  assert.equal(posture.interpretation, "bounded-lexical-posture-only");
  assert.equal(posture.indexedFileCount, 2);
  assert.equal(posture.routeCount, 3);
  assert.deepEqual(posture.routeAuth, {
    "authorization-signal-observed": 1,
    "authentication-signal-observed": 1,
    "no-auth-signal-observed": 1,
  });
  assert.deepEqual(posture.routeSinkKinds, {
    process: 1,
    filesystem: 0,
    database: 2,
    network: 0,
  });
  assert.equal(posture.routesWithSinkSignals, 2);
  assert.equal(posture.routesWithoutAuthSignals, 1);
});

test("posture summary respects the route cap", () => {
  const posture = buildRepositoryPosture(index(), { maxRoutes: 2, authRadius: 20, sinkRadius: 20 });
  assert.equal(posture.routeCount, 2);
  assert.equal(posture.routesWithoutAuthSignals, 0);
  assert.equal(posture.routesWithSinkSignals, 2);
});
