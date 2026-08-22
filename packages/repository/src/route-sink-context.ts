import type { RepositoryIndex, RouteSignal, SinkSignal } from "./analysis.js";

export interface RouteSinkEvidence {
  line: number;
  distance: number;
  kind: SinkSignal["kind"];
}

export interface RouteSinkContext {
  route: RouteSignal;
  evidence: RouteSinkEvidence[];
  kinds: SinkSignal["kind"][];
  radius: number;
  /** Lexical proximity is review evidence only, not proof of call/data-flow reachability. */
  interpretation: "lexical-sink-signals-only";
}

function normalizePath(value: string): string {
  return value.replaceAll("\\", "/").replace(/^\.\//, "").replace(/^\//, "").toLowerCase();
}

function sinkPriority(kind: SinkSignal["kind"]): number {
  if (kind === "process") return 4;
  if (kind === "database") return 3;
  if (kind === "filesystem") return 2;
  return 1;
}

export function routeSinkContext(
  index: RepositoryIndex,
  route: RouteSignal,
  options: { radius?: number; maxEvidence?: number } = {},
): RouteSinkContext {
  const radius = Math.max(0, Math.min(500, options.radius ?? 80));
  const maxEvidence = Math.max(1, Math.min(20, options.maxEvidence ?? 8));
  const routePath = normalizePath(route.path);

  const evidence = index.sinks
    .filter((signal) => normalizePath(signal.path) === routePath)
    .map((signal): RouteSinkEvidence => ({
      line: signal.line,
      distance: Math.abs(signal.line - route.line),
      kind: signal.kind,
    }))
    .filter((signal) => signal.distance <= radius)
    .sort((a, b) => {
      const distance = a.distance - b.distance;
      if (distance !== 0) return distance;
      const priority = sinkPriority(b.kind) - sinkPriority(a.kind);
      if (priority !== 0) return priority;
      return a.line - b.line;
    })
    .slice(0, maxEvidence);

  const kinds = [...new Set(evidence.map((signal) => signal.kind))];
  return {
    route,
    evidence,
    kinds,
    radius,
    interpretation: "lexical-sink-signals-only",
  };
}

export function repositoryRouteSinkContexts(
  index: RepositoryIndex,
  options: { radius?: number; maxEvidence?: number; maxRoutes?: number } = {},
): RouteSinkContext[] {
  const maxRoutes = Math.max(0, Math.min(5_000, options.maxRoutes ?? 1_000));
  return index.routes
    .slice(0, maxRoutes)
    .map((route) => routeSinkContext(index, route, options));
}
