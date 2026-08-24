import type { RouteProtectionContext, RouteProtectionStatus } from "./route-protection-context.js";
import type { RouteSinkFlowContext } from "./route-sink-flow.js";

export type RouteSecurityReviewSignal =
  | "sensitive-sink-with-authorization-signal"
  | "sensitive-sink-with-authentication-signal"
  | "sensitive-sink-without-auth-signal"
  | "sensitive-sink-auth-context-unavailable";

export interface RouteSecurityReviewContext {
  method: string;
  route: string;
  frameworkHint?: string;
  handler: string;
  sinkKinds: RouteSinkFlowContext["kinds"];
  protectionStatus: RouteProtectionStatus | "not-assessed";
  signal: RouteSecurityReviewSignal;
  callScope: "same-file" | "same-file-and-explicit-imports";
  /** Aggregate structural review context only; never runtime reachability, protection, or exploitability proof. */
  interpretation: "structural-route-security-review-context-only";
}

export interface RouteSecurityReviewSummary {
  total: number;
  needsAuthReview: number;
  signals: Record<RouteSecurityReviewSignal, number>;
  sinkKinds: Record<RouteSinkFlowContext["kinds"][number], number>;
  /** Aggregate counts derived from validated structural contexts; never a vulnerability or protection verdict. */
  interpretation: "aggregate-structural-route-security-review-only";
}

const REVIEW_SIGNALS = new Set<RouteSecurityReviewSignal>([
  "sensitive-sink-with-authorization-signal",
  "sensitive-sink-with-authentication-signal",
  "sensitive-sink-without-auth-signal",
  "sensitive-sink-auth-context-unavailable",
]);
const PROTECTION_STATUSES = new Set<RouteProtectionStatus | "not-assessed">([
  "authorization-signal-observed",
  "authentication-signal-observed",
  "no-auth-signal-observed",
  "not-assessed",
]);
const SINK_KINDS = new Set<RouteSinkFlowContext["kinds"][number]>([
  "process",
  "database",
  "filesystem",
  "network",
]);

function normalizePath(value: string): string {
  return value.replaceAll("\\", "/").replace(/^\.\//, "").replace(/^\//, "").toLowerCase();
}

function sameRoute(flow: RouteSinkFlowContext, protection: RouteProtectionContext): boolean {
  return normalizePath(flow.route.path) === normalizePath(protection.route.path)
    && flow.route.line === protection.route.line
    && flow.route.method === protection.route.method
    && flow.route.route === protection.route.route
    && flow.handler.id === protection.handler.id;
}

function signalFor(status: RouteProtectionStatus | "not-assessed"): RouteSecurityReviewSignal {
  if (status === "authorization-signal-observed") return "sensitive-sink-with-authorization-signal";
  if (status === "authentication-signal-observed") return "sensitive-sink-with-authentication-signal";
  if (status === "no-auth-signal-observed") return "sensitive-sink-without-auth-signal";
  return "sensitive-sink-auth-context-unavailable";
}

/**
 * Join already-resolved route-to-sink and route-protection contexts into a minimized route-level
 * review surface. A protection context is accepted only when exactly one structural record matches
 * the same route and handler; duplicate or missing matches become `not-assessed` rather than being
 * guessed. Routes without linked sink evidence are omitted.
 */
export function buildRouteSecurityReviewContexts(
  routeFlows: readonly RouteSinkFlowContext[],
  protections: readonly RouteProtectionContext[],
  maxRoutes = 1_000,
): RouteSecurityReviewContext[] {
  if (!Number.isSafeInteger(maxRoutes) || maxRoutes < 0 || maxRoutes > 5_000) {
    throw new Error("Route security review maxRoutes must be an integer between 0 and 5000.");
  }

  const output: RouteSecurityReviewContext[] = [];
  for (const flow of routeFlows) {
    if (output.length >= maxRoutes) break;
    if (flow.evidence.length === 0 || flow.kinds.length === 0) continue;

    const matches = protections.filter((protection) => sameRoute(flow, protection));
    const protectionStatus = matches.length === 1 && matches[0]
      ? matches[0].status
      : "not-assessed";

    output.push({
      method: flow.route.method,
      route: flow.route.route,
      ...(flow.route.frameworkHint ? { frameworkHint: flow.route.frameworkHint } : {}),
      handler: flow.handler.name,
      sinkKinds: [...flow.kinds],
      protectionStatus,
      signal: signalFor(protectionStatus),
      callScope: flow.callScope,
      interpretation: "structural-route-security-review-context-only",
    });
  }

  return output;
}

function validBoundedLabel(value: unknown): value is string {
  return typeof value === "string"
    && value.length > 0
    && value.length <= 1_024
    && !/[\u0000-\u001f\u007f]/.test(value);
}

/**
 * Derive a disclosure-minimized aggregate from route-security contexts while treating the supplied
 * records as untrusted runtime data. Signal/status mismatches, unknown sink kinds, duplicate kinds,
 * invalid labels, unsupported call scopes, and oversized collections fail closed instead of being
 * counted. The summary never copies route names, handler names, paths, framework hints, or evidence.
 */
export function summarizeRouteSecurityReviews(
  contexts: readonly RouteSecurityReviewContext[],
): RouteSecurityReviewSummary {
  if (!Array.isArray(contexts) || contexts.length > 5_000) {
    throw new Error("Route security review summary accepts at most 5000 contexts.");
  }

  const signals: RouteSecurityReviewSummary["signals"] = {
    "sensitive-sink-with-authorization-signal": 0,
    "sensitive-sink-with-authentication-signal": 0,
    "sensitive-sink-without-auth-signal": 0,
    "sensitive-sink-auth-context-unavailable": 0,
  };
  const sinkKinds: RouteSecurityReviewSummary["sinkKinds"] = {
    process: 0,
    database: 0,
    filesystem: 0,
    network: 0,
  };

  for (const context of contexts) {
    if (!context || typeof context !== "object") {
      throw new Error("Route security review summary received an invalid context.");
    }
    if (!validBoundedLabel(context.method) || !validBoundedLabel(context.route) || !validBoundedLabel(context.handler)) {
      throw new Error("Route security review summary received invalid route identity metadata.");
    }
    if (context.frameworkHint !== undefined && !validBoundedLabel(context.frameworkHint)) {
      throw new Error("Route security review summary received invalid framework metadata.");
    }
    const protectionStatus = context.protectionStatus as RouteProtectionStatus | "not-assessed";
    const signal = context.signal as RouteSecurityReviewSignal;
    if (!PROTECTION_STATUSES.has(protectionStatus)
      || !REVIEW_SIGNALS.has(signal)
      || signalFor(protectionStatus) !== signal) {
      throw new Error("Route security review summary received inconsistent protection metadata.");
    }
    if (context.callScope !== "same-file" && context.callScope !== "same-file-and-explicit-imports") {
      throw new Error("Route security review summary received an invalid call scope.");
    }
    if (context.interpretation !== "structural-route-security-review-context-only") {
      throw new Error("Route security review summary received an unsupported interpretation.");
    }
    if (!Array.isArray(context.sinkKinds) || context.sinkKinds.length < 1 || context.sinkKinds.length > SINK_KINDS.size) {
      throw new Error("Route security review summary received invalid sink metadata.");
    }
    const sinkKindValues = context.sinkKinds as RouteSinkFlowContext["kinds"][number][];
    const uniqueKinds = new Set<RouteSinkFlowContext["kinds"][number]>(sinkKindValues);
    if (uniqueKinds.size !== sinkKindValues.length || [...uniqueKinds].some((kind) => !SINK_KINDS.has(kind))) {
      throw new Error("Route security review summary received invalid sink metadata.");
    }

    signals[signal] += 1;
    for (const kind of uniqueKinds) sinkKinds[kind] += 1;
  }

  return {
    total: contexts.length,
    needsAuthReview:
      signals["sensitive-sink-without-auth-signal"]
      + signals["sensitive-sink-auth-context-unavailable"],
    signals,
    sinkKinds,
    interpretation: "aggregate-structural-route-security-review-only",
  };
}
