import { lstat, readFile } from "node:fs/promises";
import { extname, isAbsolute, relative, resolve, sep } from "node:path";
import type { IndexFileInput, SinkSignal } from "./analysis.js";
import type { CallGraph, CallGraphNode } from "./call-graph.js";
import type { ImportCallLinkGraph } from "./import-call-links.js";
import type { RequestInputKind, RequestInputSignal } from "./request-input-flow.js";
import type { RouteEntrypointResolution } from "./route-entrypoints.js";
import type { RouteSinkFlowContext } from "./route-sink-flow.js";

export interface RequestInputForwardingEvidence {
  source: {
    path: string;
    line: number;
    kind: RequestInputKind;
    frameworkFamily: RequestInputSignal["frameworkFamily"];
    access: string;
    functionId: string;
    functionName: string;
  };
  forwarding: {
    declarationLine: number;
    callLine: number;
    kind: "immutable-local-binding-direct-call-argument";
  };
  sink: {
    path: string;
    line: number;
    kind: SinkSignal["kind"];
    functionId: string;
    functionName: string;
  };
  callDistance: number;
}

export interface RouteRequestInputForwardingContext {
  route: RouteSinkFlowContext["route"];
  resolution: Exclude<RouteEntrypointResolution, "unresolved">;
  handler: RouteSinkFlowContext["handler"];
  evidence: RequestInputForwardingEvidence[];
  sourceKinds: RequestInputKind[];
  sinkKinds: SinkSignal["kind"][];
  callScope: "same-file" | "same-file-and-explicit-imports";
  interpretation: "structural-request-source-immutable-binding-call-sink-evidence-only";
}

export interface FindingRequestInputForwardingEvidence {
  method: string;
  route: string;
  frameworkHint?: string;
  resolution: Exclude<RouteEntrypointResolution, "unresolved">;
  handler: string;
  sourceKind: RequestInputKind;
  sourceFunction: string;
  sinkKind: SinkSignal["kind"];
  sinkFunction: string;
  callDistance: number;
  callScope: RouteRequestInputForwardingContext["callScope"];
  interpretation: "structural-request-source-immutable-binding-call-sink-evidence-only";
}

export interface RequestInputForwardingOptions {
  maxEvidence?: number;
  maxRoutes?: number;
  maxCallNodes?: number;
  maxForwardLines?: number;
}

const MAX_SOURCE_BYTES = 512_000;
const MAX_FILES = 5_000;
const MAX_FORWARD_LINES = 40;
const jsExtensions = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"]);

function normalizedPath(value: string): string {
  return value.replaceAll("\\", "/").replace(/^\.\//, "");
}

function comparisonPath(value: string): string {
  return normalizedPath(value).replace(/^\//, "").toLowerCase();
}

function insideRoot(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

async function readBoundedSource(root: string, file: IndexFileInput): Promise<string[] | undefined> {
  if (file.size > MAX_SOURCE_BYTES || !jsExtensions.has(extname(file.path).toLowerCase())) return undefined;
  const path = normalizedPath(file.path);
  if (!path || path.includes("\0") || path.startsWith("../") || isAbsolute(file.path)) return undefined;
  const absolute = resolve(root, path);
  if (!insideRoot(root, absolute)) return undefined;
  const info = await lstat(absolute).catch(() => undefined);
  if (!info?.isFile() || info.isSymbolicLink() || info.size > MAX_SOURCE_BYTES) return undefined;
  const content = await readFile(absolute, "utf8").catch(() => undefined);
  if (content === undefined || content.includes("\u0000")) return undefined;
  return content.split(/\r?\n/);
}

function owningFunction(graph: CallGraph, path: string, line: number): CallGraphNode | undefined {
  const normalized = comparisonPath(path);
  const matches = graph.nodes.filter(
    (node) => comparisonPath(node.path) === normalized && line >= node.line && line <= node.endLine,
  );
  return matches.length === 1 ? matches[0] : undefined;
}

function graphAdjacency(
  graph: CallGraph,
  importCallLinks: ImportCallLinkGraph,
): { targets: Map<string, string[]>; importedEdges: Set<string> } {
  const targets = new Map<string, Set<string>>();
  const importedEdges = new Set<string>();
  const add = (from: string, target: string): void => {
    const bucket = targets.get(from) ?? new Set<string>();
    bucket.add(target);
    targets.set(from, bucket);
  };
  for (const edge of graph.edges) if (edge.target) add(edge.from, edge.target);
  for (const link of importCallLinks.links) {
    add(link.from, link.target);
    importedEdges.add(`${link.from}\u0000${link.target}`);
  }
  return {
    targets: new Map([...targets].map(([from, values]) => [from, [...values].sort()])),
    importedEdges,
  };
}

function reachableDepths(
  start: string,
  targets: ReadonlyMap<string, readonly string[]>,
  maxDepth: number,
  maxNodes: number,
): Map<string, number> {
  const depths = new Map<string, number>([[start, 0]]);
  const queue: Array<{ id: string; depth: number }> = [{ id: start, depth: 0 }];
  while (queue.length > 0 && depths.size < maxNodes) {
    const current = queue.shift();
    if (!current || current.depth >= maxDepth) continue;
    for (const next of targets.get(current.id) ?? []) {
      if (depths.has(next)) continue;
      depths.set(next, current.depth + 1);
      queue.push({ id: next, depth: current.depth + 1 });
      if (depths.size >= maxNodes) break;
    }
  }
  return depths;
}

function shortestPath(
  start: string,
  target: string,
  adjacency: ReturnType<typeof graphAdjacency>,
  allowed: ReadonlySet<string>,
  maxDepth: number,
  maxNodes: number,
): { distance: number; usedImport: boolean } | undefined {
  if (start === target) return { distance: 0, usedImport: false };
  const queue: Array<{ id: string; depth: number; usedImport: boolean }> = [{ id: start, depth: 0, usedImport: false }];
  const seen = new Set<string>([start]);
  let examined = 0;
  while (queue.length > 0 && examined < maxNodes) {
    const current = queue.shift();
    if (!current || current.depth >= maxDepth) continue;
    examined += 1;
    for (const next of adjacency.targets.get(current.id) ?? []) {
      if (!allowed.has(next) || seen.has(next)) continue;
      const usedImport = current.usedImport || adjacency.importedEdges.has(`${current.id}\u0000${next}`);
      if (next === target) return { distance: current.depth + 1, usedImport };
      seen.add(next);
      queue.push({ id: next, depth: current.depth + 1, usedImport });
    }
  }
  return undefined;
}

function simpleRequestBinding(line: string): string | undefined {
  const match = /^\s*const\s+([A-Za-z_$][\w$]*)\s*=\s*((?:req|request)\.(?:body|query|params|headers|cookies|files?)(?:\.[A-Za-z_$][\w$]*|\[["'][^"'\r\n]{1,64}["']\])*)\s*;?\s*$/.exec(line);
  return match?.[1];
}

function identifierPattern(identifier: string): RegExp {
  return new RegExp(`(^|[^A-Za-z0-9_$])${identifier.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}([^A-Za-z0-9_$]|$)`);
}

function directCallCallees(line: string, identifier: string): string[] {
  const output = new Set<string>();
  const calls = /\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(([^()]*)\)/g;
  for (let match = calls.exec(line); match; match = calls.exec(line)) {
    const callee = match[1];
    const args = match[2];
    if (!callee || args === undefined) continue;
    const values = args.split(",").map((value) => value.trim());
    if (values.includes(identifier)) output.add(callee);
  }
  return [...output].sort();
}

function resolvedTargetAtLine(
  graph: CallGraph,
  importCallLinks: ImportCallLinkGraph,
  owner: CallGraphNode,
  line: number,
  callees: readonly string[],
): { target: string; usedImport: boolean } | undefined {
  const candidates = new Map<string, boolean>();
  for (const edge of graph.edges) {
    if (edge.from !== owner.id || edge.line !== line || !edge.target || !callees.includes(edge.callee)) continue;
    candidates.set(edge.target, candidates.get(edge.target) ?? false);
  }
  for (const link of importCallLinks.links) {
    if (link.from !== owner.id || link.line !== line || !callees.includes(link.callee)) continue;
    candidates.set(link.target, true);
  }
  if (candidates.size !== 1) return undefined;
  const [entry] = candidates.entries();
  const first = entry.next().value as [string, boolean] | undefined;
  return first ? { target: first[0], usedImport: first[1] } : undefined;
}

function forwardingTarget(
  lines: readonly string[],
  signal: RequestInputSignal,
  owner: CallGraphNode,
  graph: CallGraph,
  importCallLinks: ImportCallLinkGraph,
  maxForwardLines: number,
): { callLine: number; target: string; usedImport: boolean } | undefined {
  const declaration = lines[signal.line - 1] ?? "";
  const binding = simpleRequestBinding(declaration);
  if (!binding) return undefined;
  const identifier = identifierPattern(binding);
  const end = Math.min(owner.endLine, signal.line + maxForwardLines);
  let candidate: { callLine: number; target: string; usedImport: boolean } | undefined;

  for (let lineNumber = signal.line + 1; lineNumber <= owner.endLine; lineNumber += 1) {
    const line = lines[lineNumber - 1] ?? "";
    if (!identifier.test(line)) continue;
    if (lineNumber > end) return undefined;
    if (/^\s*(?:\/\/|\/\*|\*)/.test(line)) continue;
    if (candidate) return undefined;
    if (new RegExp(`\\b${binding.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*(?:=|\\+=|-=|\\*=|\/=|%=|\\+\\+|--)`).test(line)) return undefined;
    const callees = directCallCallees(line, binding);
    if (callees.length === 0) return undefined;
    const resolved = resolvedTargetAtLine(graph, importCallLinks, owner, lineNumber, callees);
    if (!resolved) return undefined;
    candidate = { callLine: lineNumber, target: resolved.target, usedImport: resolved.usedImport };
  }
  return candidate;
}

/**
 * Add one deliberately narrow level of local data-flow evidence without claiming general taint.
 * Only JS/TS `const x = req.<supported-access>...` declarations are eligible. The immutable binding
 * must have exactly one later use in the same lexical function, within a bounded line distance, and
 * that use must be an unchanged direct argument to exactly one resolved local/imported call. Any
 * mutation, validation/sanitization step, transformation, aliasing, multiple use, unresolved call,
 * destructuring, nested expression, Python assignment, or ambiguity is omitted.
 */
export async function repositoryRouteRequestInputForwardingContexts(
  rootPath: string,
  files: readonly IndexFileInput[],
  requestInputs: readonly RequestInputSignal[],
  routeFlows: readonly RouteSinkFlowContext[],
  graph: CallGraph,
  importCallLinks: ImportCallLinkGraph,
  options: RequestInputForwardingOptions = {},
): Promise<RouteRequestInputForwardingContext[]> {
  const root = resolve(rootPath);
  const maxRoutes = Math.max(0, Math.min(5_000, options.maxRoutes ?? 1_000));
  const maxEvidence = Math.max(1, Math.min(50, options.maxEvidence ?? 12));
  const maxNodes = Math.max(1, Math.min(1_000, options.maxCallNodes ?? 100));
  const maxForwardLines = Math.max(1, Math.min(MAX_FORWARD_LINES, options.maxForwardLines ?? 12));
  const fileMap = new Map(files.slice(0, MAX_FILES).map((file) => [comparisonPath(file.path), file]));
  const sourceCache = new Map<string, string[] | undefined>();
  const adjacency = graphAdjacency(graph, importCallLinks);
  const output: RouteRequestInputForwardingContext[] = [];

  for (const routeFlow of routeFlows.slice(0, maxRoutes)) {
    const maxDepth = Math.max(0, Math.min(12, routeFlow.maxDepth));
    const routeDepths = reachableDepths(routeFlow.handler.id, adjacency.targets, maxDepth, maxNodes);
    const routeNodes = new Set(routeDepths.keys());
    const evidence: RequestInputForwardingEvidence[] = [];
    let usedImport = false;

    for (const signal of requestInputs) {
      if (signal.frameworkFamily !== "node-request") continue;
      const owner = owningFunction(graph, signal.path, signal.line);
      if (!owner || !routeNodes.has(owner.id)) continue;
      const fileKey = comparisonPath(signal.path);
      const file = fileMap.get(fileKey);
      if (!file) continue;
      let lines = sourceCache.get(fileKey);
      if (!sourceCache.has(fileKey)) {
        lines = await readBoundedSource(root, file);
        sourceCache.set(fileKey, lines);
      }
      if (!lines) continue;
      const forwarding = forwardingTarget(lines, signal, owner, graph, importCallLinks, maxForwardLines);
      if (!forwarding || !routeNodes.has(forwarding.target)) continue;

      for (const sink of routeFlow.evidence) {
        const path = shortestPath(
          forwarding.target,
          sink.functionId,
          adjacency,
          routeNodes,
          Math.max(0, maxDepth - 1),
          maxNodes,
        );
        if (!path) continue;
        usedImport = usedImport || forwarding.usedImport || path.usedImport;
        evidence.push({
          source: {
            path: signal.path,
            line: signal.line,
            kind: signal.kind,
            frameworkFamily: signal.frameworkFamily,
            access: signal.access,
            functionId: owner.id,
            functionName: owner.name,
          },
          forwarding: {
            declarationLine: signal.line,
            callLine: forwarding.callLine,
            kind: "immutable-local-binding-direct-call-argument",
          },
          sink: {
            path: sink.path,
            line: sink.line,
            kind: sink.kind,
            functionId: sink.functionId,
            functionName: sink.functionName,
          },
          callDistance: 1 + path.distance,
        });
        if (evidence.length >= maxEvidence) break;
      }
      if (evidence.length >= maxEvidence) break;
    }

    if (evidence.length === 0) continue;
    evidence.sort((a, b) =>
      a.callDistance - b.callDistance ||
      a.source.path.localeCompare(b.source.path) || a.source.line - b.source.line ||
      a.sink.path.localeCompare(b.sink.path) || a.sink.line - b.sink.line,
    );
    output.push({
      route: routeFlow.route,
      resolution: routeFlow.resolution,
      handler: routeFlow.handler,
      evidence,
      sourceKinds: [...new Set(evidence.map((item) => item.source.kind))],
      sinkKinds: [...new Set(evidence.map((item) => item.sink.kind))],
      callScope: usedImport ? "same-file-and-explicit-imports" : "same-file",
      interpretation: "structural-request-source-immutable-binding-call-sink-evidence-only",
    });
  }
  return output;
}

/** Correlate only to the exact sink line already linked through the bounded immutable forwarding rule. */
export function findingRequestInputForwardingEvidence(
  contexts: readonly RouteRequestInputForwardingContext[],
  path: string,
  line: number | undefined,
  maxRoutes = 3,
): FindingRequestInputForwardingEvidence[] {
  if (!Number.isSafeInteger(line) || (line ?? 0) <= 0) return [];
  const normalized = comparisonPath(path);
  const limit = Math.max(1, Math.min(10, maxRoutes));
  const output: FindingRequestInputForwardingEvidence[] = [];
  for (const context of contexts) {
    const match = context.evidence.find(
      (item) => comparisonPath(item.sink.path) === normalized && item.sink.line === line,
    );
    if (!match) continue;
    output.push({
      method: context.route.method,
      route: context.route.route,
      ...(context.route.frameworkHint ? { frameworkHint: context.route.frameworkHint } : {}),
      resolution: context.resolution,
      handler: context.handler.name,
      sourceKind: match.source.kind,
      sourceFunction: match.source.functionName,
      sinkKind: match.sink.kind,
      sinkFunction: match.sink.functionName,
      callDistance: match.callDistance,
      callScope: context.callScope,
      interpretation: "structural-request-source-immutable-binding-call-sink-evidence-only",
    });
    if (output.length >= limit) break;
  }
  return output;
}
