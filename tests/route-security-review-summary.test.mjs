import assert from "node:assert/strict";
import test from "node:test";
import { summarizeRouteSecurityReviews } from "@synsec/repository/route-security-review";

function review(overrides = {}) {
  return {
    method: "POST",
    route: "/admin/run",
    frameworkHint: "Node HTTP router",
    handler: "runAdminJob",
    sinkKinds: ["process", "database"],
    protectionStatus: "authorization-signal-observed",
    signal: "sensitive-sink-with-authorization-signal",
    callScope: "same-file-and-explicit-imports",
    interpretation: "structural-route-security-review-context-only",
    ...overrides,
  };
}

test("route security review summary derives deterministic minimized counts", () => {
  const summary = summarizeRouteSecurityReviews([
    review(),
    review({
      route: "/jobs",
      sinkKinds: ["database"],
      protectionStatus: "no-auth-signal-observed",
      signal: "sensitive-sink-without-auth-signal",
    }),
    review({
      route: "/health",
      sinkKinds: ["network"],
      protectionStatus: "not-assessed",
      signal: "sensitive-sink-auth-context-unavailable",
    }),
  ]);
  assert.deepEqual(summary, {
    total: 3,
    needsAuthReview: 2,
    signals: {
      "sensitive-sink-with-authorization-signal": 1,
      "sensitive-sink-with-authentication-signal": 0,
      "sensitive-sink-without-auth-signal": 1,
      "sensitive-sink-auth-context-unavailable": 1,
    },
    sinkKinds: { process: 1, database: 2, filesystem: 0, network: 1 },
    interpretation: "aggregate-structural-route-security-review-only",
  });
  const serialized = JSON.stringify(summary);
  assert.equal(serialized.includes("/admin/run"), false);
  assert.equal(serialized.includes("runAdminJob"), false);
  assert.equal(serialized.includes("Node HTTP router"), false);
});

test("summary fails closed on signal/status tampering and malformed sink metadata", () => {
  assert.throws(
    () => summarizeRouteSecurityReviews([review({ signal: "sensitive-sink-without-auth-signal" })]),
    /inconsistent protection metadata/,
  );
  assert.throws(
    () => summarizeRouteSecurityReviews([review({ sinkKinds: ["database", "database"] })]),
    /invalid sink metadata/,
  );
  assert.throws(
    () => summarizeRouteSecurityReviews([review({ sinkKinds: ["unknown"] })]),
    /invalid sink metadata/,
  );
});

test("summary rejects control-bearing identity metadata without reflecting it", () => {
  const token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
  assert.throws(
    () => summarizeRouteSecurityReviews([review({ route: `/admin/${token}\n` })]),
    (error) => {
      assert.doesNotMatch(error.message, new RegExp(token));
      assert.match(error.message, /invalid route identity metadata/);
      return true;
    },
  );
});

test("summary bounds collection size and zero route review limits remain compatible", async () => {
  assert.throws(
    () => summarizeRouteSecurityReviews(Array.from({ length: 5_001 }, () => review())),
    /at most 5000 contexts/,
  );
});
