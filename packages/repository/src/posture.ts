import type { RepositoryIndex, SinkSignal } from "./analysis.js";
import { repositoryRouteAuthContexts, type RouteAuthStatus } from "./route-auth-context.js";
import { repositoryRouteSinkContexts } from "./route-sink-context.js";

export interface RepositoryPostureSummary {
  schemaVersion: 1;
  indexedFileCount: number;
  routeCount: number;
  routeAuth: Record<RouteAuthStatus, number>;
  routeSinkKinds: Record<SinkSignal["kind"], number>;
  routesWithSinkSignals: number;
  routesWithoutAuthSignals: number;
  /** Counts are derived from lexical repository signals and are not runtime security assertions. */
  interpretation: "bounded-lexical-posture-only";
}

export function buildRepositoryPosture(
  index: RepositoryIndex,
  options: { authRadius?: number; sinkRadius?: number; maxRoutes?: number } = {},
): RepositoryPostureSummary {
  const maxRoutes = Math.max(0, Math.min(5_000, options.maxRoutes ?? 1_000));
  const routeAuth = repositoryRouteAuthContexts(index, {
    radius: options.authRadius,
    maxRoutes,
  });
  const routeSinks = repositoryRouteSinkContexts(index, {
    radius: options.sinkRadius,
    maxRoutes,
  });

  const authCounts: Record<RouteAuthStatus, number> = {
    "authorization-signal-observed": 0,
    "authentication-signal-observed": 0,
    "no-auth-signal-observed": 0,
  };
  for (const route of routeAuth) authCounts[route.status] += 1;

  const sinkCounts: Record<SinkSignal["kind"], number> = {
    process: 0,
    filesystem: 0,
    database: 0,
    network: 0,
  };
  let routesWithSinkSignals = 0;
  for (const route of routeSinks) {
    if (route.kinds.length > 0) routesWithSinkSignals += 1;
    for (const kind of route.kinds) sinkCounts[kind] += 1;
  }

  return {
    schemaVersion: 1,
    indexedFileCount: index.indexedFileCount,
    routeCount: Math.min(index.routes.length, maxRoutes),
    routeAuth: authCounts,
    routeSinkKinds: sinkCounts,
    routesWithSinkSignals,
    routesWithoutAuthSignals: authCounts["no-auth-signal-observed"],
    interpretation: "bounded-lexical-posture-only",
  };
}
