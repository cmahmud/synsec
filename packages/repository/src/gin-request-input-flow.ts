import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { SinkSignal } from "./analysis.js";
import type { CallGraph, CallGraphNode } from "./call-graph.js";
import type { RouteSinkFlowContext } from "./route-sink-flow.js";

export type GinRequestInputKind = "body" | "query" | "path" | "header" | "cookie";

export interface GinRequestInputEvidence {
  source: {
    path: string;
    line: number;
    kind: GinRequestInputKind;
    access: string;
    functionId: string;
    functionName: string;
  };
  sink: {
    path: string;
    line: number;
    kind: SinkSignal["kind"];
    functionId: string;
    functionName: string;
  };
  callDistance: 0 | 1;
}

export interface GinRouteRequestInputFlowContext {
  route: RouteSinkFlowContext["route"];
  resolution: RouteSinkFlowContext["resolution"];
  handler: RouteSinkFlowContext["handler"];
  evidence: GinRequestInputEvidence[];
  sourceKinds: GinRequestInputKind[];
  sinkKinds: SinkSignal["kind"][];
  interpretation: "structural-gin-context-source-direct-call-sink-evidence-only";
}

export interface FindingGinRequestInputFlowEvidence {
  method: string;
  route: string;
  frameworkHint?: string;
  handler: string;
  sourceKind: GinRequestInputKind;
  sourceFunction: string;
  sinkKind: SinkSignal["kind"];
  sinkFunction: string;
  callDistance: 0 | 1;
  interpretation: "structural-gin-context-source-direct-call-sink-evidence-only";
}

export interface GinRequestInputFlowOptions {
  maxFiles?: number;
  maxSourceBytes?: number;
  maxEvidence?: number;
  maxRoutes?: number;
}

const DEFAULT_MAX_FILES = 5_000;
const MAX_FILES = 5_000;
const DEFAULT_MAX_SOURCE_BYTES = 512_000;
const MAX_SOURCE_BYTES = 2_000_000;
const DEFAULT_MAX_EVIDENCE = 12;
const MAX_EVIDENCE = 50;
const DEFAULT_MAX_ROUTES = 1_000;
const MAX_ROUTES = 5_000;

function boundedInteger(value: number | undefined, fallback: number, maximum: number, label: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < 1 || resolved > maximum) {
    throw new Error(`${label} must be an integer between 1 and ${maximum}.`);
  }
  return resolved;
}

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

function ginContextParameter(node: CallGraphNode, lines: readonly string[]): string | undefined {
  const declaration = lines[node.line - 1] ?? "";
  if (!/^\s*func\b/.test(declaration)) return undefined;
  const contexts = [...declaration.matchAll(/\b([A-Za-z_][\w]*)\s+\*gin\.Context\b/g)].map((match) => match[1]);
  return contexts.length === 1 ? contexts[0] : undefined;
}

function requestAccesses(line: string, contextName: string): Array<{ kind: GinRequestInputKind; access: string }> {
  const output: Array<{ kind: GinRequestInputKind; access: string }> = [];
  const regex = /\b([A-Za-z_][\w]*)\.(Query|PostForm|Param|GetHeader|Cookie)\s*\(/g;
  for (let match = regex.exec(line); match; match = regex.exec(line)) {
    if (match[1] !== contextName) continue;
    const member = match[2];
    if (member === "Query") output.push({ kind: "query", access: "gin.Context.Query" });
    else if (member === "PostForm") output.push({ kind: "body", access: "gin.Context.PostForm" });
    else if (member === "Param") output.push({ kind: "path", access: "gin.Context.Param" });
    else if (member === "GetHeader") output.push({ kind: "header", access: "gin.Context.GetHeader" });
    else if (member === "Cookie") output.push({ kind: "cookie", access: "gin.Context.Cookie" });
  }
  return output;
}

async function readSafeGoFiles(
  rootPath: string,
  graph: CallGraph,
  options: GinRequestInputFlowOptions,
): Promise<Map<string, string[]>> {
  const root = resolve(rootPath);
  const maxFiles = boundedInteger(options.maxFiles, DEFAULT_MAX_FILES, MAX_FILES, "Gin request-flow maxFiles");
  const maxSourceBytes = boundedInteger(
    options.maxSourceBytes,
    DEFAULT_MAX_SOURCE_BYTES,
    MAX_SOURCE_BYTES,
    "Gin request-flow maxSourceBytes",
  );
  const paths = [...new Set(graph.nodes.filter((node) => node.path.toLowerCase().endsWith(".go")).map((node) => normalizedPath(node.path)))].slice(0, maxFiles);
  const output = new Map<string, string[]>();

  for (const path of paths) {
    if (!path || path.includes("\0") || path.startsWith("../") || isAbsolute(path)) continue;
    const absolute = resolve(root, path);
    if (!insideRoot(root, absolute)) continue;
    const info = await lstat(absolute).catch(() => undefined);
    if (!info?.isFile() || info.isSymbolicLink() || info.size > maxSourceBytes) continue;
    const source = await readFile(absolute, "utf8").catch(() => undefined);
    if (!source || source.includes("\u0000")) continue;
    output.set(comparisonPath(path), source.split(/\r?\n/));
  }
  return output;
}

function directTargets(graph: CallGraph, ownerId: string, line: number): string[] {
  return [...new Set(graph.edges.flatMap((edge) => edge.from === ownerId && edge.line === line && edge.target ? [edge.target] : []))].sort();
}

/**
 * Build deliberately narrow Gin request-source evidence from route flows already resolved by the
 * strict Gin router composer. The source must be an explicit accessor on the exact `*gin.Context`
 * parameter of a reachable Go function. The source line must either contain the exact sink itself
 * or a direct call-graph edge to the sink-owning function. Bound-object APIs such as
 * ShouldBind/BindJSON are intentionally excluded because proving the resulting variable flow would
 * require a broader data-flow model.
 */
export async function buildGinRouteRequestInputFlowContexts(
  rootPath: string,
  routeFlows: readonly RouteSinkFlowContext[],
  graph: CallGraph,
  options: GinRequestInputFlowOptions = {},
): Promise<GinRouteRequestInputFlowContext[]> {
  const maxEvidence = boundedInteger(options.maxEvidence, DEFAULT_MAX_EVIDENCE, MAX_EVIDENCE, "Gin request-flow maxEvidence");
  const maxRoutes = boundedInteger(options.maxRoutes, DEFAULT_MAX_ROUTES, MAX_ROUTES, "Gin request-flow maxRoutes");
  const files = await readSafeGoFiles(rootPath, graph, options);
  const output: GinRouteRequestInputFlowContext[] = [];

  for (const routeFlow of routeFlows.slice(0, maxRoutes)) {
    if (routeFlow.route.frameworkHint !== "Gin router") continue;
    const reachableIds = new Set<string>([routeFlow.handler.id, ...routeFlow.evidence.map((item) => item.functionId)]);
    const evidence: GinRequestInputEvidence[] = [];

    for (const node of graph.nodes) {
      if (!reachableIds.has(node.id) || node.kind !== "go-function") continue;
      const lines = files.get(comparisonPath(node.path));
      if (!lines) continue;
      const contextName = ginContextParameter(node, lines);
      if (!contextName) continue;

      for (let lineNumber = node.line; lineNumber <= node.endLine && evidence.length < maxEvidence; lineNumber += 1) {
        const accesses = requestAccesses(lines[lineNumber - 1] ?? "", contextName);
        if (accesses.length === 0) continue;
        const targets = new Set(directTargets(graph, node.id, lineNumber));

        for (const sink of routeFlow.evidence) {
          const distance: 0 | 1 | undefined = sink.functionId === node.id && sink.line === lineNumber
            ? 0
            : targets.has(sink.functionId) ? 1 : undefined;
          if (distance === undefined) continue;
          for (const source of accesses) {
            evidence.push({
              source: {
                path: node.path,
                line: lineNumber,
                kind: source.kind,
                access: source.access,
                functionId: node.id,
                functionName: node.name,
              },
              sink: {
                path: sink.path,
                line: sink.line,
                kind: sink.kind,
                functionId: sink.functionId,
                functionName: sink.functionName,
              },
              callDistance: distance,
            });
            if (evidence.length >= maxEvidence) break;
          }
          if (evidence.length >= maxEvidence) break;
        }
      }
      if (evidence.length >= maxEvidence) break;
    }

    if (evidence.length === 0) continue;
    output.push({
      route: routeFlow.route,
      resolution: routeFlow.resolution,
      handler: routeFlow.handler,
      evidence,
      sourceKinds: [...new Set(evidence.map((item) => item.source.kind))],
      sinkKinds: [...new Set(evidence.map((item) => item.sink.kind))],
      interpretation: "structural-gin-context-source-direct-call-sink-evidence-only",
    });
  }
  return output;
}

/** Return only aggregate structural evidence for an exact finding sink line. */
export function findingGinRequestInputFlowEvidence(
  contexts: readonly GinRouteRequestInputFlowContext[],
  path: string,
  line: number | undefined,
  maxRoutes = 3,
): FindingGinRequestInputFlowEvidence[] {
  if (!Number.isSafeInteger(line) || (line ?? 0) <= 0) return [];
  const normalized = comparisonPath(path);
  const limit = Math.max(1, Math.min(10, maxRoutes));
  const output: FindingGinRequestInputFlowEvidence[] = [];
  for (const context of contexts) {
    for (const item of context.evidence) {
      if (comparisonPath(item.sink.path) !== normalized || item.sink.line !== line) continue;
      output.push({
        method: context.route.method,
        route: context.route.route,
        ...(context.route.frameworkHint ? { frameworkHint: context.route.frameworkHint } : {}),
        handler: context.handler.name,
        sourceKind: item.source.kind,
        sourceFunction: item.source.functionName,
        sinkKind: item.sink.kind,
        sinkFunction: item.sink.functionName,
        callDistance: item.callDistance,
        interpretation: "structural-gin-context-source-direct-call-sink-evidence-only",
      });
      if (output.length >= limit) return output;
    }
  }
  return output;
}
