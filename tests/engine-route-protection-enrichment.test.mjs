import assert from "node:assert/strict";
import test from "node:test";
import { enrichRepositorySecurityContext } from "../packages/engine/dist/index.js";

const route = {
  path: "server.ts",
  line: 5,
  method: "POST",
  route: "/admin/run",
  frameworkHint: "Node HTTP router",
  handler: "runAdminJob",
};

const index = {
  schemaVersion: 1,
  generatedAt: "2026-08-23T19:00:00.000Z",
  indexedFileCount: 2,
  moduleEdges: [],
  routes: [route],
  authSignals: [],
  sinks: [{ path: "service.ts", line: 44, kind: "process", evidence: "exec(command)" }],
};

const routeFlows = [{
  route,
  resolution: "named-function",
  handler: {
    id: "server.ts:runAdminJob:20",
    name: "runAdminJob",
    path: "server.ts",
    line: 20,
    endLine: 25,
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

const routeProtections = [{
  route,
  resolution: "named-function",
  handler: {
    id: "server.ts:runAdminJob:20",
    name: "runAdminJob",
    path: "server.ts",
    line: 20,
    endLine: 25,
  },
  status: "authorization-signal-observed",
  evidence: [{
    path: "auth.ts",
    line: 12,
    kind: "authorization",
    source: "reachable-function",
    functionName: "checkRole",
    depth: 1,
  }],
  callScope: "same-file-and-explicit-imports",
  interpretation: "structural-auth-signals-not-protection-proof",
}];

function scan(category = "sast", line = 44) {
  return {
    scanner: "fixture",
    startedAt: "2026-08-23T19:00:00.000Z",
    completedAt: "2026-08-23T19:00:01.000Z",
    target: { path: "/repo" },
    diagnostics: [],
    findings: [{
      id: "fixture",
      title: "Process execution finding",
      category,
      severity: "high",
      confidence: 0.9,
      scanner: { name: "fixture" },
      location: { path: "service.ts", startLine: line },
    }],
  };
}

test("engine enrichment attaches minimized route protection only to exact route-sink findings", () => {
  const [enriched] = enrichRepositorySecurityContext([scan()], index, routeFlows, routeProtections);
  const metadata = enriched.findings[0].metadata;

  assert.deepEqual(metadata.routeProtection, [{
    method: "POST",
    route: "/admin/run",
    frameworkHint: "Node HTTP router",
    resolution: "named-function",
    handler: "runAdminJob",
    status: "authorization-signal-observed",
    evidenceKinds: ["authorization"],
    callScope: "same-file-and-explicit-imports",
    interpretation: "structural-auth-signals-not-protection-proof",
  }]);
  const serialized = JSON.stringify(metadata.routeProtection);
  assert.equal(serialized.includes("auth.ts"), false);
  assert.equal(serialized.includes("checkRole"), false);
  assert.equal(serialized.includes("exec(command)"), false);
});

test("engine enrichment does not attach route protection to a different finding line", () => {
  const [enriched] = enrichRepositorySecurityContext([scan("sast", 45)], index, routeFlows, routeProtections);
  assert.equal(enriched.findings[0].metadata?.routeProtection, undefined);
});

test("secret findings remain outside repository and route protection enrichment", () => {
  const original = scan("secret");
  original.findings[0].metadata = { scannerOwned: "preserved" };
  const [enriched] = enrichRepositorySecurityContext([original], index, routeFlows, routeProtections);
  assert.deepEqual(enriched.findings[0].metadata, { scannerOwned: "preserved" });
});
