import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { SinkSignal } from "./analysis.js";
import type { CallGraph, CallGraphNode } from "./call-graph.js";
import type { GinRequestInputKind } from "./gin-request-input-flow.js";
import type { RouteSinkFlowContext } from "./route-sink-flow.js";

export interface GinRequestInputForwardingEvidence {
  source: {
    path: string;
    line: number;
    kind: Exclude<GinRequestInputKind, "cookie">;
    functionId: string;
    functionName: string;
  };
  binding: {
    line: number;
    useLine: number;
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

export interface GinRouteRequestInputForwardingContext {
  route: RouteSinkFlowContext["route"];
  resolution: RouteSinkFlowContext["resolution"];
  handler: RouteSinkFlowContext["handler"];
  evidence: GinRequestInputForwardingEvidence[];
  sourceKinds: Array<Exclude<GinRequestInputKind, "cookie">>;
  sinkKinds: SinkSignal["kind"][];
  interpretation: "structural-gin-context-source-single-use-local-call-sink-evidence-only";
}

export interface FindingGinRequestInputForwardingEvidence {
  method: string;
  route: string;
  frameworkHint?: string;
  handler: string;
  sourceKind: Exclude<GinRequestInputKind, "cookie">;
  sourceFunction: string;
  sinkKind: SinkSignal["kind"];
  sinkFunction: string;
  callDistance: 0 | 1;
  bindingHops: 1;
  interpretation: "structural-gin-context-source-single-use-local-call-sink-evidence-only";
}

export interface GinRequestInputForwardingOptions {
  maxFiles?: number;
  maxSourceBytes?: number;
  maxEvidence?: number;
  maxRoutes?: number;
  maxForwardLines?: number;
}

const DEFAULT_MAX_FILES = 5_000;
const MAX_FILES = 5_000;
const DEFAULT_MAX_SOURCE_BYTES = 512_000;
const MAX_SOURCE_BYTES = 2_000_000;
const DEFAULT_MAX_EVIDENCE = 12;
const MAX_EVIDENCE = 50;
const DEFAULT_MAX_ROUTES = 1_000;
const MAX_ROUTES = 5_000;
const DEFAULT_MAX_FORWARD_LINES = 8;
const MAX_FORWARD_LINES = 50;

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

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function ginContextParameter(node: CallGraphNode, lines: readonly string[]): string | undefined {
  const declaration = lines[node.line - 1] ?? "";
  if (!/^\s*func\b/.test(declaration)) return undefined;
  const contexts = [...declaration.matchAll(/\b([A-Za-z_][\w]*)\s+\*gin\.Context\b/g)].map((match) => match[1]);
  return contexts.length === 1 ? contexts[0] : undefined;
}

function sourceBinding(
  line: string,
  contextName: string,
): { name: string; kind: Exclude<GinRequestInputKind, "cookie"> } | undefined {
  const context = escapeRegex(contextName);
  const match = new RegExp(
    `^\\s*([A-Za-z_][\\w]*)\\s*:=\\s*${context}\\.(Query|PostForm|Param|GetHeader)\\s*\\([^\\r\\n]*\\)\\s*$`,
  ).exec(line);
  if (!match) return undefined;
  const member = match[2];
  const kind: Exclude<GinRequestInputKind, "cookie"> = member === "PostForm"
    ? "body"
    : member === "Param"
      ? "path"
      : member === "GetHeader"
        ? "header"
        : "query";
  return { name: match[1]!, kind };
}

function exactSingleArgumentCall(line: string, binding: string): boolean {
  const value = escapeRegex(binding);
  return new RegExp(
    `^\\s*[A-Za-z_][\\w]*(?:\\.[A-Za-z_][\\w]*)?\\s*\\(\\s*${value}\\s*\\)\\s*$`,
  ).test(line);
}

function wordOccurrences(lines: readonly string[], startLine: number, endLine: number, name: string): number[] {
  const output: number[] = [];
  const pattern = new RegExp(`\\b${escapeRegex(name)}\\b`, "g");
  for (let lineNumber = startLine; lineNumber <= endLine; lineNumber += 1) {
    const line = lines[lineNumber - 1] ?? "";
    pattern.lastIndex = 0;
    let count = 0;
    while (pattern.exec(line)) count += 1;
    for (let index = 0; index < count; index += 1) output.push(lineNumber);
  }
  return output;
}

async function readSafeGoFiles(
  rootPath: string,
  graph: CallGraph,
  options: GinRequestInputForwardingOptions,
): Promise<Map<string, string[]>> {
  const root = resolve(rootPath);
  const maxFiles = boundedInteger(options.maxFiles, DEFAULT_MAX_FILES, MAX_FILES, "Gin request-forwarding maxFiles");
  const maxSourceBytes = boundedInteger(
    options.maxSourceBytes,
    DEFAULT_MAX_SOURCE_BYTES,
    MAX_SOURCE_BYTES,
    "Gin request-forwarding maxSourceBytes",
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
 * Recognize one deliberately narrow Go forwarding shape:
 *
 *   value := c.Query("key")
 *   sink(value)
 *
 * The binding must have exactly one occurrence after its declaration anywhere in the containing
 * function, that use must remain within maxForwardLines, and the use line must be exactly one
 * single-argument call. This excludes reassignment, multiple use, transformation, aliasing and
 * wider propagation without pretending Go locals are immutable by language semantics.
 */
export async function buildGinRouteRequestInputForwardingContexts(
  rootPath: string,
  routeFlows: readonly RouteSinkFlowContext[],
  graph: CallGraph,
  options: GinRequestInputForwardingOptions = {},
): Promise<GinRouteRequestInputForwardingContext[]> {
  const maxEvidence = boundedInteger(options.maxEvidence, DEFAULT_MAX_EVIDENCE, MAX_EVIDENCE, "Gin request-forwarding maxEvidence");
  const maxRoutes = boundedInteger(options.maxRoutes, DEFAULT_MAX_ROUTES, MAX_ROUTES, "Gin request-forwarding maxRoutes");
  const maxForwardLines = boundedInteger(
    options.maxForwardLines,
    DEFAULT_MAX_FORWARD_LINES,
    MAX_FORWARD_LINES,
    "Gin request-forwarding maxForwardLines",
  );
  const files = await readSafeGoFiles(rootPath, graph, options);
  const output: GinRouteRequestInputForwardingContext[] = [];

  for (const routeFlow of routeFlows.slice(0, maxRoutes)) {
    if (routeFlow.route.frameworkHint !== "Gin router") continue;
    const reachableIds = new Set<string>([routeFlow.handler.id, ...routeFlow.evidence.map((item) => item.functionId)]);
    const evidence: GinRequestInputForwardingEvidence[] = [];

    for (const node of graph.nodes) {
      if (!reachableIds.has(node.id) || node.kind !== "go-function") continue;
      const lines = files.get(comparisonPath(node.path));
      if (!lines) continue;
      const contextName = ginContextParameter(node, lines);
      if (!contextName) continue;

      for (let sourceLine = node.line + 1; sourceLine <= node.endLine && evidence.length < maxEvidence; sourceLine += 1) {
        const binding = sourceBinding(lines[sourceLine - 1] ?? "", contextName);
        if (!binding) continue;
        const occurrences = wordOccurrences(lines, sourceLine + 1, node.endLine, binding.name);
        if (occurrences.length !== 1) continue;
        const useLine = occurrences[0]!;
        if (useLine - sourceLine > maxForwardLines) continue;
        const useText = lines[useLine - 1] ?? "";
        if (!exactSingleArgumentCall(useText, binding.name)) continue;
        const targets = new Set(directTargets(graph, node.id, useLine));

        for (const sink of routeFlow.evidence) {
          const sameLineSink = sink.functionId === node.id && sink.line === useLine;
          const distance: 0 | 1 | undefined = sameLineSink ? 0 : targets.has(sink.functionId) ? 1 : undefined;
          if (distance === undefined) continue;
          evidence.push({
            source: {
              path: node.path,
              line: sourceLine,
              kind: binding.kind,
              functionId: node.id,
              functionName: node.name,
            },
            binding: { line: sourceLine, useLine },
            sink: {
              path: sink.path,
              line: sink.line,
              kind: sink.kind,
              functionId: sink.functionId,
              functionName: sink.functionName,
            },
            callDistance: distance,
          });
          break;
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
      interpretation: "structural-gin-context-source-single-use-local-call-sink-evidence-only",
    });
  }
  return output;
}

/** Return aggregate structural evidence for an exact finding sink line without source keys/values. */
export function findingGinRequestInputForwardingEvidence(
  contexts: readonly GinRouteRequestInputForwardingContext[],
  path: string,
  line: number | undefined,
  maxRoutes = 3,
): FindingGinRequestInputForwardingEvidence[] {
  if (!Number.isSafeInteger(line) || (line ?? 0) <= 0) return [];
  const normalized = comparisonPath(path);
  const limit = Math.max(1, Math.min(10, maxRoutes));
  const output: FindingGinRequestInputForwardingEvidence[] = [];
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
        bindingHops: 1,
        interpretation: "structural-gin-context-source-single-use-local-call-sink-evidence-only",
      });
      if (output.length >= limit) return output;
    }
  }
  return output;
}
