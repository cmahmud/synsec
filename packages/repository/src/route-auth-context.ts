import type { AuthSignal, RepositoryIndex, RouteSignal } from "./analysis.js";

export type RouteAuthStatus =
  | "authorization-signal-observed"
  | "authentication-signal-observed"
  | "no-auth-signal-observed";

export interface RouteAuthEvidence {
  line: number;
  distance: number;
  kind: AuthSignal["kind"];
}

export interface RouteAuthContext {
  route: RouteSignal;
  status: RouteAuthStatus;
  evidence: RouteAuthEvidence[];
  radius: number;
  /** Lexical proximity is evidence for review prioritization, not proof of route protection. */
  interpretation: "lexical-auth-signals-only";
}

function normalizePath(value: string): string {
  return value.replaceAll("\\", "/").replace(/^\.\//, "").replace(/^\//, "").toLowerCase();
}

function authPriority(kind: AuthSignal["kind"]): number {
  if (kind === "authorization") return 4;
  if (kind === "authentication") return 3;
  if (kind === "token") return 2;
  return 1;
}

export function routeAuthContext(
  index: RepositoryIndex,
  route: RouteSignal,
  options: { radius?: number; maxEvidence?: number } = {},
): RouteAuthContext {
  const radius = Math.max(0, Math.min(500, options.radius ?? 40));
  const maxEvidence = Math.max(1, Math.min(20, options.maxEvidence ?? 5));
  const routePath = normalizePath(route.path);

  const evidence = index.authSignals
    .filter((signal) => normalizePath(signal.path) === routePath)
    .map((signal): RouteAuthEvidence => ({
      line: signal.line,
      distance: Math.abs(signal.line - route.line),
      kind: signal.kind,
    }))
    .filter((signal) => signal.distance <= radius)
    .sort((a, b) => {
      const priority = authPriority(b.kind) - authPriority(a.kind);
      if (priority !== 0) return priority;
      return a.distance - b.distance || a.line - b.line;
    })
    .slice(0, maxEvidence);

  const status: RouteAuthStatus = evidence.some((signal) => signal.kind === "authorization")
    ? "authorization-signal-observed"
    : evidence.length > 0
      ? "authentication-signal-observed"
      : "no-auth-signal-observed";

  return {
    route,
    status,
    evidence,
    radius,
    interpretation: "lexical-auth-signals-only",
  };
}

export function repositoryRouteAuthContexts(
  index: RepositoryIndex,
  options: { radius?: number; maxEvidence?: number; maxRoutes?: number } = {},
): RouteAuthContext[] {
  const maxRoutes = Math.max(0, Math.min(5_000, options.maxRoutes ?? 1_000));
  return index.routes
    .slice(0, maxRoutes)
    .map((route) => routeAuthContext(index, route, options));
}
