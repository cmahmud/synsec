import assert from "node:assert/strict";
import test from "node:test";
import { buildRouteSecurityReviewContexts } from "@synsec/repository/route-security-review";

const route = {
  path: "server.ts",
  line: 8,
  method: "POST",
  route: "/admin/run",
  frameworkHint: "Node HTTP router",
};

const handler = {
  id: "server.ts:runAdminJob:20",
  name: "runAdminJob",
  path: "server.ts",
  line: 20,
  endLine: 30,
};

function flow(overrides = {}) {
  return {
    route,
    resolution: "named-function",
    handler,
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
    ...overrides,
  };
}

function protection(status = "authorization-signal-observed") {
  return {
    route,
    resolution: "named-function",
    handler,
    status,
    evidence: [{
      path: "auth.ts",
      line: 12,
      kind: "authorization",
      source: "reachable-function",
      functionName: "assertRole",
      depth: 1,
    }],
    callScope: "same-file-and-explicit-imports",
    interpretation: "structural-auth-signals-not-protection-proof",
  };
}

test("route security review summarizes sink and auth context without source evidence", () => {
  const contexts = buildRouteSecurityReviewContexts([flow()], [protection()]);
  assert.deepEqual(contexts, [{
    method: "POST",
    route: "/admin/run",
    frameworkHint: "Node HTTP router",
    handler: "runAdminJob",
    sinkKinds: ["process"],
    protectionStatus: "authorization-signal-observed",
    signal: "sensitive-sink-with-authorization-signal",
    callScope: "same-file-and-explicit-imports",
    interpretation: "structural-route-security-review-context-only",
  }]);
  const serialized = JSON.stringify(contexts);
  assert.equal(serialized.includes("auth.ts"), false);
  assert.equal(serialized.includes("assertRole"), false);
  assert.equal(serialized.includes("service.ts"), false);
  assert.equal(serialized.includes("execJob"), false);
});

test("missing or duplicate auth context fails closed to not-assessed", () => {
  assert.equal(
    buildRouteSecurityReviewContexts([flow()], [])[0].signal,
    "sensitive-sink-auth-context-unavailable",
  );
  assert.equal(
    buildRouteSecurityReviewContexts([flow()], [protection(), protection()])[0].protectionStatus,
    "not-assessed",
  );
});

test("observed authentication and absence of auth signals remain explicitly structural", () => {
  assert.equal(
    buildRouteSecurityReviewContexts([flow()], [protection("authentication-signal-observed")])[0].signal,
    "sensitive-sink-with-authentication-signal",
  );
  assert.equal(
    buildRouteSecurityReviewContexts([flow()], [protection("no-auth-signal-observed")])[0].signal,
    "sensitive-sink-without-auth-signal",
  );
});

test("routes without linked sink evidence are omitted and route bounds are validated", () => {
  assert.deepEqual(buildRouteSecurityReviewContexts([flow({ evidence: [], kinds: [] })], [protection()]), []);
  assert.deepEqual(buildRouteSecurityReviewContexts([flow()], [protection()], 0), []);
  assert.throws(() => buildRouteSecurityReviewContexts([flow()], [protection()], -1), /between 0 and 5000/);
  assert.throws(() => buildRouteSecurityReviewContexts([flow()], [protection()], 5_001), /between 0 and 5000/);
});
