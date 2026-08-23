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
  if (!Number.isSafeInteger(maxRoutes) || maxRoutes < 1 || maxRoutes > 5_000) {
    throw new Error("Route security review maxRoutes must be an integer between 1 and 5000.");
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
