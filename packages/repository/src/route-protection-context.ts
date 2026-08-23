import type { AuthSignal, RepositoryIndex, RouteSignal } from "./analysis.js";
import type { CallGraph, CallGraphNode } from "./call-graph.js";
import type { ImportCallLinkGraph } from "./import-call-links.js";
import type { RouteEntrypoint, RouteEntrypointResolution } from "./route-entrypoints.js";
import type { RouteSinkFlowContext } from "./route-sink-flow.js";

export type RouteProtectionStatus =
  | "authorization-signal-observed"
  | "authentication-signal-observed"
  | "no-auth-signal-observed";

export interface RouteProtectionEvidence {
  path: string;
  line: number;
  kind: AuthSignal["kind"];
  source: "route-registration" | "reachable-function";
  functionName?: string;
  depth?: number;
}

export interface RouteProtectionContext {
  route: RouteSignal;
  resolution: Exclude<RouteEntrypointResolution, "unresolved">;
  handler: {
    id: string;
    name: string;
    path: string;
    line: number;
    endLine: number;
  };
  status: RouteProtectionStatus;
  evidence: RouteProtectionEvidence[];
  callScope: "same-file" | "same-file-and-explicit-imports";
  /** Static auth-related tokens are review context only and do not prove effective route protection. */
  interpretation: "structural-auth-signals-not-protection-proof";
}

export interface FindingRouteProtectionEvidence {
  method: string;
  route: string;
  frameworkHint?: string;
  resolution: Exclude<RouteEntrypointResolution, "unresolved">;
  handler: string;
  status: RouteProtectionStatus;
  evidenceKinds: AuthSignal["kind"][];
  callScope: "same-file" | "same-file-and-explicit-imports";
  /** Correlated structural evidence only; never an authorization or exploitability verdict. */
  interpretation: "structural-auth-signals-not-protection-proof";
}

export interface RouteProtectionOptions {
  maxEvidence?: number;
  maxRoutes?: number;
  maxCallNodes?: number;
  importCallLinks?: ImportCallLinkGraph;
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

function statusFromEvidence(evidence: readonly RouteProtectionEvidence[]): RouteProtectionStatus {
  if (evidence.some((item) => item.kind === "authorization")) return "authorization-signal-observed";
  if (evidence.length > 0) return "authentication-signal-observed";
  return "no-auth-signal-observed";
}

function reachableDepths(
  entrypoint: RouteEntrypoint,
  graph: CallGraph,
  importCallLinks: ImportCallLinkGraph | undefined,
  maxCallNodes: number,
): { depths: Map<string, number>; usedImportLink: boolean } {
  const depths = new Map<string, number>();
  if (!entrypoint.handler || entrypoint.resolution === "unresolved") return { depths, usedImportLink: false };

  const maxDepth = Math.max(0, entrypoint.calls?.maxDepth ?? 0);
  const nodeLimit = Math.max(1, Math.min(1_000, maxCallNodes));
  const queue: Array<{ id: string; depth: number }> = [{ id: entrypoint.handler.id, depth: 0 }];
  depths.set(entrypoint.handler.id, 0);
  let usedImportLink = false;

  while (queue.length > 0 && depths.size < nodeLimit) {
    const current = queue.shift();
    if (!current || current.depth >= maxDepth) continue;
    const sameFileTargets = graph.edges.flatMap((edge) => edge.from === current.id && edge.target ? [edge.target] : []);
    const importedTargets = importCallLinks?.links.flatMap((link) => link.from === current.id ? [link.target] : []) ?? [];
    const importedSet = new Set(importedTargets);
    const adjacent = [...new Set([...sameFileTargets, ...importedTargets])].sort();
    for (const id of adjacent) {
      if (depths.has(id)) continue;
      const nextDepth = current.depth + 1;
      depths.set(id, nextDepth);
      if (importedSet.has(id)) usedImportLink = true;
      queue.push({ id, depth: nextDepth });
      if (depths.size >= nodeLimit) break;
    }
  }

  return { depths, usedImportLink };
}

function owningReachableFunction(
  graph: CallGraph,
  depths: ReadonlyMap<string, number>,
  signal: AuthSignal,
): { node: CallGraphNode; depth: number } | undefined {
  const path = normalizePath(signal.path);
  const candidates = graph.nodes.filter((node) => {
    if (!depths.has(node.id) || normalizePath(node.path) !== path) return false;
    return signal.line >= node.line && signal.line <= node.endLine;
  });
  if (candidates.length !== 1) return undefined;
  const node = candidates[0];
  if (!node) return undefined;
  const depth = depths.get(node.id);
  return depth === undefined ? undefined : { node, depth };
}

/**
 * Correlate one resolved route with auth-related lexical signals at its registration and inside its
 * bounded call neighborhood. This is deliberately not a protection verdict: middleware may be
 * ineffective, branches may bypass checks, and auth-related names may be unrelated to enforcement.
 */
export function routeProtectionContext(
  index: RepositoryIndex,
  entrypoint: RouteEntrypoint,
  graph: CallGraph,
  options: RouteProtectionOptions = {},
): RouteProtectionContext | undefined {
  if (!entrypoint.handler || entrypoint.resolution === "unresolved") return undefined;
  const maxEvidence = Math.max(1, Math.min(50, options.maxEvidence ?? 12));
  const reachability = reachableDepths(entrypoint, graph, options.importCallLinks, options.maxCallNodes ?? 100);
  const routePath = normalizePath(entrypoint.route.path);

  const registrationEvidence = index.authSignals
    .filter((signal) => normalizePath(signal.path) === routePath && signal.line === entrypoint.route.line)
    .map((signal): RouteProtectionEvidence => ({
      path: signal.path,
      line: signal.line,
      kind: signal.kind,
      source: "route-registration",
    }));

  const reachableEvidence = index.authSignals
    .map((signal): RouteProtectionEvidence | undefined => {
      const owner = owningReachableFunction(graph, reachability.depths, signal);
      if (!owner) return undefined;
      return {
        path: signal.path,
        line: signal.line,
        kind: signal.kind,
        source: "reachable-function",
        functionName: owner.node.name,
        depth: owner.depth,
      };
    })
    .filter((value): value is RouteProtectionEvidence => Boolean(value));

  const evidence = [...registrationEvidence, ...reachableEvidence]
    .sort((a, b) => authPriority(b.kind) - authPriority(a.kind)
      || (a.depth ?? -1) - (b.depth ?? -1)
      || a.path.localeCompare(b.path)
      || a.line - b.line)
    .slice(0, maxEvidence);

  return {
    route: entrypoint.route,
    resolution: entrypoint.resolution,
    handler: {
      id: entrypoint.handler.id,
      name: entrypoint.handler.name,
      path: entrypoint.handler.path,
      line: entrypoint.handler.line,
      endLine: entrypoint.handler.endLine,
    },
    status: statusFromEvidence(evidence),
    evidence,
    callScope: reachability.usedImportLink ? "same-file-and-explicit-imports" : "same-file",
    interpretation: "structural-auth-signals-not-protection-proof",
  };
}

export function repositoryRouteProtectionContexts(
  index: RepositoryIndex,
  entrypoints: readonly RouteEntrypoint[],
  graph: CallGraph,
  options: RouteProtectionOptions = {},
): RouteProtectionContext[] {
  const maxRoutes = Math.max(0, Math.min(5_000, options.maxRoutes ?? 1_000));
  const output: RouteProtectionContext[] = [];
  for (const entrypoint of entrypoints.slice(0, maxRoutes)) {
    const context = routeProtectionContext(index, entrypoint, graph, options);
    if (context) output.push(context);
  }
  return output;
}

function sameRoute(a: RouteSignal, b: RouteSignal): boolean {
  return normalizePath(a.path) === normalizePath(b.path)
    && a.line === b.line
    && a.method === b.method
    && a.route === b.route;
}

/**
 * Return minimized route-protection context only for routes whose structural sink flow exactly
 * matches the finding location. Source lines and raw auth evidence are intentionally omitted.
 */
export function findingRouteProtectionEvidence(
  protections: readonly RouteProtectionContext[],
  routeFlows: readonly RouteSinkFlowContext[],
  path: string,
  line: number | undefined,
  maxRoutes = 3,
): FindingRouteProtectionEvidence[] {
  if (!Number.isSafeInteger(line) || (line ?? 0) <= 0) return [];
  const normalized = normalizePath(path);
  const limit = Math.max(1, Math.min(10, maxRoutes));
  const output: FindingRouteProtectionEvidence[] = [];

  for (const flow of routeFlows) {
    const sinkMatch = flow.evidence.some((item) => normalizePath(item.path) === normalized && item.line === line);
    if (!sinkMatch) continue;
    const protection = protections.find((item) => sameRoute(item.route, flow.route) && item.handler.id === flow.handler.id);
    if (!protection) continue;
    output.push({
      method: protection.route.method,
      route: protection.route.route,
      ...(protection.route.frameworkHint ? { frameworkHint: protection.route.frameworkHint } : {}),
      resolution: protection.resolution,
      handler: protection.handler.name,
      status: protection.status,
      evidenceKinds: [...new Set(protection.evidence.map((item) => item.kind))],
      callScope: protection.callScope,
      interpretation: "structural-auth-signals-not-protection-proof",
    });
    if (output.length >= limit) break;
  }
  return output;
}
