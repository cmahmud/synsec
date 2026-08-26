import type { RepositoryIndex, RouteSignal } from "./analysis.js";
import type { CallGraph, CallGraphNode, CallNeighborhood } from "./call-graph.js";
import { findCallNeighborhood } from "./call-graph.js";

export type RouteEntrypointResolution =
  | "decorated-function"
  | "named-function"
  | "imported-named-function"
  | "unresolved";

export interface RouteEntrypoint {
  route: RouteSignal;
  resolution: RouteEntrypointResolution;
  handler?: CallGraphNode;
  calls?: CallNeighborhood;
  /** Route-to-handler mapping and downstream calls are static structural evidence, not runtime reachability proof. */
  interpretation: "structural-route-call-evidence-only";
}

function normalizePath(value: string): string {
  return value.replaceAll("\\", "/").replace(/^\.\//, "");
}

function isDecoratorRoute(route: RouteSignal): boolean {
  return route.frameworkHint === "Decorator router" || route.frameworkHint === "Python web router";
}

function decoratedHandler(
  route: RouteSignal,
  graph: CallGraph,
  maxDeclarationDistance: number,
): CallGraphNode | undefined {
  if (!isDecoratorRoute(route)) return undefined;
  const routePath = normalizePath(route.path);
  const boundedDistance = Math.max(1, Math.min(20, maxDeclarationDistance));
  const candidates = graph.nodes
    .filter((node) => {
      if (normalizePath(node.path) !== routePath) return false;
      const distance = node.line - route.line;
      return distance > 0 && distance <= boundedDistance;
    })
    .sort((a, b) => a.line - b.line || a.name.localeCompare(b.name));

  const first = candidates[0];
  if (!first) return undefined;
  const nearestDistance = first.line - route.line;
  const nearest = candidates.filter((candidate) => candidate.line - route.line === nearestDistance);
  return nearest.length === 1 ? nearest[0] : undefined;
}

function namedNodeHandler(route: RouteSignal, graph: CallGraph): CallGraphNode | undefined {
  if (route.frameworkHint !== "Node HTTP router" || !route.handler) return undefined;
  const routePath = normalizePath(route.path);
  const candidates = graph.nodes.filter(
    (node) => normalizePath(node.path) === routePath && node.name === route.handler,
  );
  return candidates.length === 1 ? candidates[0] : undefined;
}

export function resolveRouteEntrypoints(
  index: RepositoryIndex,
  graph: CallGraph,
  options: { maxDeclarationDistance?: number; maxCallDepth?: number; maxCallNodes?: number } = {},
): RouteEntrypoint[] {
  const maxDeclarationDistance = options.maxDeclarationDistance ?? 5;
  const maxCallDepth = options.maxCallDepth ?? 3;
  const maxCallNodes = options.maxCallNodes ?? 100;

  return index.routes.map((route) => {
    const decorated = decoratedHandler(route, graph, maxDeclarationDistance);
    const named = decorated ? undefined : namedNodeHandler(route, graph);
    const handler = decorated ?? named;
    if (!handler) {
      return {
        route,
        resolution: "unresolved",
        interpretation: "structural-route-call-evidence-only",
      };
    }

    return {
      route,
      resolution: decorated ? "decorated-function" : "named-function",
      handler,
      calls: findCallNeighborhood(graph, handler.id, maxCallDepth, maxCallNodes),
      interpretation: "structural-route-call-evidence-only",
    };
  });
}

export function routeEntrypointForLocation(
  entrypoints: readonly RouteEntrypoint[],
  path: string,
  line: number,
): RouteEntrypoint | undefined {
  const normalized = normalizePath(path);
  return entrypoints.find((entrypoint) => {
    const handler = entrypoint.handler;
    if (!handler || normalizePath(handler.path) !== normalized) return false;
    return line >= handler.line && line <= handler.endLine;
  });
}
