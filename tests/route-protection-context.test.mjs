import assert from "node:assert/strict";
import test from "node:test";
import {
  findingRouteProtectionEvidence,
  routeProtectionContext,
} from "@synsec/repository/route-protection-context";

const route = {
  path: "server.ts",
  line: 5,
  method: "POST",
  route: "/admin/run",
  frameworkHint: "Node HTTP router",
  handler: "runAdminJob",
};

const handler = {
  id: "server.ts:runAdminJob:20",
  path: "server.ts",
  name: "runAdminJob",
  line: 20,
  endLine: 25,
  kind: "function",
};

const authorize = {
  id: "auth.ts:checkRole:10",
  path: "auth.ts",
  name: "checkRole",
  line: 10,
  endLine: 15,
  kind: "function",
};

const graph = {
  schemaVersion: 1,
  nodes: [handler, authorize],
  edges: [{
    from: handler.id,
    callee: "auth.checkRole",
    line: 22,
    resolution: "external-or-unresolved",
  }],
  resolvedEdgeCount: 0,
  unresolvedEdgeCount: 1,
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
    callees: [],
    callers: [],
    interpretation: "lexical-call-evidence-only",
  },
  interpretation: "structural-route-call-evidence-only",
};

const importCallLinks = {
  schemaVersion: 1,
  links: [{
    from: handler.id,
    line: 22,
    callee: "auth.checkRole",
    target: authorize.id,
    targetPath: "auth.ts",
    importedName: "checkRole",
    bindingKind: "javascript-namespace-import",
    evidence: "explicit-import-binding-to-unique-local-function",
  }],
  linkedCallCount: 1,
  interpretation: "cross-module-import-call-evidence-only",
};

function indexWithAuth() {
  return {
    schemaVersion: 1,
    generatedAt: "2026-08-23T18:00:00.000Z",
    indexedFileCount: 2,
    moduleEdges: [],
    routes: [route],
    authSignals: [
      { path: "server.ts", line: 5, kind: "authentication", evidence: "router.post('/admin/run', requireAuth, runAdminJob)" },
      { path: "auth.ts", line: 12, kind: "authorization", evidence: "assertRole(user, 'admin')" },
    ],
    sinks: [],
  };
}

test("route protection context correlates registration and imported reachable auth signals without source text", () => {
  const context = routeProtectionContext(indexWithAuth(), entrypoint, graph, { importCallLinks });
  assert.equal(context.status, "authorization-signal-observed");
  assert.equal(context.callScope, "same-file-and-explicit-imports");
  assert.deepEqual(context.evidence.map((item) => [item.kind, item.source, item.functionName, item.depth]), [
    ["authorization", "reachable-function", "checkRole", 1],
    ["authentication", "route-registration", undefined, undefined],
  ]);
  assert.equal(context.interpretation, "structural-auth-signals-not-protection-proof");
  const serialized = JSON.stringify(context);
  assert.equal(serialized.includes("requireAuth"), false);
  assert.equal(serialized.includes("assertRole"), false);
  assert.equal(serialized.includes("admin')"), false);
});

test("auth-looking signals outside the bounded route neighborhood do not manufacture protection", () => {
  const index = {
    ...indexWithAuth(),
    authSignals: [{ path: "other.ts", line: 300, kind: "authorization", evidence: "isAdmin" }],
  };
  const context = routeProtectionContext(index, entrypoint, graph, { importCallLinks });
  assert.equal(context.status, "no-auth-signal-observed");
  assert.deepEqual(context.evidence, []);
});

test("ambiguous function ownership is omitted rather than treated as protection evidence", () => {
  const overlapping = {
    ...graph,
    nodes: [
      ...graph.nodes,
      { id: "auth.ts:nested:11", path: "auth.ts", name: "nested", line: 11, endLine: 14, kind: "function" },
    ],
  };
  const links = {
    ...importCallLinks,
    links: [
      ...importCallLinks.links,
      {
        ...importCallLinks.links[0],
        target: "auth.ts:nested:11",
        importedName: "nested",
      },
    ],
    linkedCallCount: 2,
  };
  const context = routeProtectionContext(indexWithAuth(), entrypoint, overlapping, { importCallLinks: links });
  assert.equal(context.status, "authentication-signal-observed");
  assert.deepEqual(context.evidence.map((item) => item.kind), ["authentication"]);
});

test("finding protection evidence is emitted only when a route flow exactly matches the finding sink", () => {
  const protection = routeProtectionContext(indexWithAuth(), entrypoint, graph, { importCallLinks });
  const routeFlows = [{
    route,
    resolution: "named-function",
    handler: {
      id: handler.id,
      name: handler.name,
      path: handler.path,
      line: handler.line,
      endLine: handler.endLine,
    },
    evidence: [{
      path: "service.ts",
      line: 44,
      kind: "process",
      functionId: "service.ts:execJob:40",
      functionName: "execJob",
      depth: 2,
    }],
    kinds: ["process"],
    maxDepth: 3,
    callScope: "same-file-and-explicit-imports",
    interpretation: "structural-route-call-sink-evidence-only",
  }];

  const evidence = findingRouteProtectionEvidence([protection], routeFlows, "./service.ts", 44);
  assert.deepEqual(evidence, [{
    method: "POST",
    route: "/admin/run",
    frameworkHint: "Node HTTP router",
    resolution: "named-function",
    handler: "runAdminJob",
    status: "authorization-signal-observed",
    evidenceKinds: ["authorization", "authentication"],
    callScope: "same-file-and-explicit-imports",
    interpretation: "structural-auth-signals-not-protection-proof",
  }]);
  assert.deepEqual(findingRouteProtectionEvidence([protection], routeFlows, "service.ts", 45), []);
});
