import type { RepositoryIndex, RouteSignal, SinkSignal } from "./analysis.js";
import type { CallGraph, CallGraphNode } from "./call-graph.js";
import type { ImportCallLinkGraph } from "./import-call-links.js";
import type { RouteEntrypoint, RouteEntrypointResolution } from "./route-entrypoints.js";

export interface RouteSinkFlowEvidence {
  path: string;
  line: number;
  kind: SinkSignal["kind"];
  functionId: string;
  functionName: string;
  depth: number;
}

export interface RouteSinkFlowContext {
  route: RouteSignal;
  resolution: Exclude<RouteEntrypointResolution, "unresolved">;
  handler: {
    id: string;
    name: string;
    path: string;
    line: number;
    endLine: number;
  };
  evidence: RouteSinkFlowEvidence[];
  kinds: SinkSignal["kind"][];
  maxDepth: number;
  callScope: "same-file" | "same-file-and-explicit-imports";
  /** Static route/function/call/sink linkage is review evidence, not runtime or attacker reachability proof. */
  interpretation: "structural-route-call-sink-evidence-only";
}

export interface FindingRouteSinkFlowEvidence {
  method: string;
  route: string;
  frameworkHint?: string;
  resolution: Exclude<RouteEntrypointResolution, "unresolved">;
  handler: string;
  sinkKind: SinkSignal["kind"];
  functionName: string;
  depth: number;
  callScope: "same-file" | "same-file-and-explicit-imports";
  /** Exact-line structural linkage only; never runtime or attacker reachability proof. */
  interpretation: "structural-route-call-sink-evidence-only";
}

export interface RouteSinkFlowOptions {
  maxEvidence?: number;
  maxRoutes?: number;
  maxCallNodes?: number;
  importCallLinks?: ImportCallLinkGraph;
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

function reachableDepths(
  entrypoint: RouteEntrypoint,
  graph: CallGraph,
  importCallLinks: ImportCallLinkGraph | undefined,
  maxCallNodes: number,
): { depths: Map<string, number>; usedImportLink: boolean } {
  const depths = new Map<string, number>();
  if (!entrypoint.handler || entrypoint.resolution === "unresolved") return { depths, usedImportLink: false };

  if (!importCallLinks) {
    depths.set(entrypoint.handler.id, 0);
    for (const callee of entrypoint.calls?.callees ?? []) {
      const current = depths.get(callee.id);
      if (current === undefined || callee.depth < current) depths.set(callee.id, callee.depth);
    }
    return { depths, usedImportLink: false };
  }

  const maxDepth = Math.max(0, entrypoint.calls?.maxDepth ?? 0);
  const nodeLimit = Math.max(1, Math.min(1_000, maxCallNodes));
  const queue: Array<{ id: string; depth: number }> = [{ id: entrypoint.handler.id, depth: 0 }];
  depths.set(entrypoint.handler.id, 0);
  let usedImportLink = false;

  while (queue.length > 0 && depths.size < nodeLimit) {
    const current = queue.shift();
    if (!current || current.depth >= maxDepth) continue;
    const sameFileTargets = graph.edges.flatMap((edge) => edge.from === current.id && edge.target ? [edge.target] : []);
    const importedTargets = importCallLinks.links.flatMap((link) => link.from === current.id ? [link.target] : []);
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
  signal: SinkSignal,
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
 * Link one already-resolved route entrypoint to sink signals located inside its bounded lexical
 * call neighborhood. When an import-call graph is supplied, traversal may additionally cross an
 * explicit repository-local import binding that resolves to one unique lexical target function.
 * Ambiguous function ownership or import resolution is omitted rather than guessed.
 */
export function routeSinkFlowContext(
  index: RepositoryIndex,
  entrypoint: RouteEntrypoint,
  graph: CallGraph,
  options: RouteSinkFlowOptions = {},
): RouteSinkFlowContext | undefined {
  if (!entrypoint.handler || entrypoint.resolution === "unresolved") return undefined;
  const maxEvidence = Math.max(1, Math.min(50, options.maxEvidence ?? 12));
  const reachability = reachableDepths(entrypoint, graph, options.importCallLinks, options.maxCallNodes ?? 100);
  if (reachability.depths.size === 0) return undefined;

  const evidence = index.sinks
    .map((signal): RouteSinkFlowEvidence | undefined => {
      const owner = owningReachableFunction(graph, reachability.depths, signal);
      if (!owner) return undefined;
      return {
        path: signal.path,
        line: signal.line,
        kind: signal.kind,
        functionId: owner.node.id,
        functionName: owner.node.name,
        depth: owner.depth,
      };
    })
    .filter((value): value is RouteSinkFlowEvidence => Boolean(value))
    .sort((a, b) => a.depth - b.depth || sinkPriority(b.kind) - sinkPriority(a.kind) || a.path.localeCompare(b.path) || a.line - b.line)
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
    evidence,
    kinds: [...new Set(evidence.map((signal) => signal.kind))],
    maxDepth: entrypoint.calls?.maxDepth ?? 0,
    callScope: reachability.usedImportLink ? "same-file-and-explicit-imports" : "same-file",
    interpretation: "structural-route-call-sink-evidence-only",
  };
}

export function repositoryRouteSinkFlowContexts(
  index: RepositoryIndex,
  entrypoints: readonly RouteEntrypoint[],
  graph: CallGraph,
  options: RouteSinkFlowOptions = {},
): RouteSinkFlowContext[] {
  const maxRoutes = Math.max(0, Math.min(5_000, options.maxRoutes ?? 1_000));
  const output: RouteSinkFlowContext[] = [];
  for (const entrypoint of entrypoints.slice(0, maxRoutes)) {
    const context = routeSinkFlowContext(index, entrypoint, graph, options);
    if (context) output.push(context);
  }
  return output;
}

/** Return sanitized structural route-flow evidence only when the finding location exactly matches a linked sink line. */
export function findingRouteSinkFlowEvidence(
  contexts: readonly RouteSinkFlowContext[],
  path: string,
  line: number | undefined,
  maxRoutes = 3,
): FindingRouteSinkFlowEvidence[] {
  if (!Number.isSafeInteger(line) || (line ?? 0) <= 0) return [];
  const normalized = normalizePath(path);
  const limit = Math.max(1, Math.min(10, maxRoutes));
  const output: FindingRouteSinkFlowEvidence[] = [];

  for (const context of contexts) {
    const match = context.evidence.find(
      (evidence) => normalizePath(evidence.path) === normalized && evidence.line === line,
    );
    if (!match) continue;
    output.push({
      method: context.route.method,
      route: context.route.route,
      ...(context.route.frameworkHint ? { frameworkHint: context.route.frameworkHint } : {}),
      resolution: context.resolution,
      handler: context.handler.name,
      sinkKind: match.kind,
      functionName: match.functionName,
      depth: match.depth,
      callScope: context.callScope,
      interpretation: "structural-route-call-sink-evidence-only",
    });
    if (output.length >= limit) break;
  }
  return output;
}
