import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { SinkSignal } from "./analysis.js";
import type { CallGraph, CallGraphNode } from "./call-graph.js";
import type { KoaRequestInputKind } from "./koa-request-input-flow.js";
import type { RouteSinkFlowContext } from "./route-sink-flow.js";

export interface KoaRequestInputForwardingEvidence {
  source: {
    path: string;
    line: number;
    kind: KoaRequestInputKind;
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

export interface KoaRouteRequestInputForwardingContext {
  route: RouteSinkFlowContext["route"];
  resolution: RouteSinkFlowContext["resolution"];
  handler: RouteSinkFlowContext["handler"];
  evidence: KoaRequestInputForwardingEvidence[];
  sourceKinds: KoaRequestInputKind[];
  sinkKinds: SinkSignal["kind"][];
  interpretation: "structural-koa-context-source-single-use-local-call-sink-evidence-only";
}

export interface FindingKoaRequestInputForwardingEvidence {
  method: string;
  route: string;
  frameworkHint?: string;
  handler: string;
  sourceKind: KoaRequestInputKind;
  sourceFunction: string;
  sinkKind: SinkSignal["kind"];
  sinkFunction: string;
  callDistance: 0 | 1;
  bindingHops: 1;
  interpretation: "structural-koa-context-source-single-use-local-call-sink-evidence-only";
}

export interface KoaRequestInputForwardingOptions {
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

function handlerContextParameter(node: CallGraphNode, lines: readonly string[]): string | undefined {
  if (node.kind !== "function" && node.kind !== "arrow-function") return undefined;
  const declaration = lines[node.line - 1] ?? "";
  let parameters: string | undefined;
  if (node.kind === "function") {
    const match = declaration.match(/\b(?:async\s+)?function\s+[A-Za-z_$][\w$]*\s*\(([^)]*)\)/);
    parameters = match?.[1];
  } else {
    const parenthesized = declaration.match(/\b(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/);
    if (parenthesized) parameters = parenthesized[1];
    else {
      const single = declaration.match(/\b(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*(?:async\s*)?([A-Za-z_$][\w$]*)\s*=>/);
      parameters = single?.[1];
    }
  }
  if (parameters === undefined) return undefined;
  const first = parameters.split(",")[0]?.trim();
  return first && /^[A-Za-z_$][\w$]*$/.test(first) ? first : undefined;
}

function sourceBinding(line: string, contextName: string): { name: string; kind: KoaRequestInputKind } | undefined {
  const context = escapeRegex(contextName);
  const prefix = "^\\s*const\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*";
  const suffix = "\\s*;?\\s*$";
  const candidates: Array<[KoaRequestInputKind, RegExp]> = [
    ["body", new RegExp(`${prefix}${context}\\.request\\.body(?:\\.[A-Za-z_$][\\w$]*|\\[[^\\r\\n]+\\])?${suffix}`)],
    ["query", new RegExp(`${prefix}${context}\\.query(?:\\.[A-Za-z_$][\\w$]*|\\[[^\\r\\n]+\\])?${suffix}`)],
    ["query", new RegExp(`${prefix}${context}\\.request\\.query(?:\\.[A-Za-z_$][\\w$]*|\\[[^\\r\\n]+\\])?${suffix}`)],
    ["path", new RegExp(`${prefix}${context}\\.params(?:\\.[A-Za-z_$][\\w$]*|\\[[^\\r\\n]+\\])?${suffix}`)],
    ["header", new RegExp(`${prefix}${context}\\.headers(?:\\.[A-Za-z_$][\\w$]*|\\[[^\\r\\n]+\\])?${suffix}`)],
    ["header", new RegExp(`${prefix}${context}\\.request\\.headers(?:\\.[A-Za-z_$][\\w$]*|\\[[^\\r\\n]+\\])?${suffix}`)],
    ["header", new RegExp(`${prefix}${context}\\.get\\s*\\([^\\r\\n]*\\)${suffix}`)],
    ["cookie", new RegExp(`${prefix}${context}\\.cookies\\.get\\s*\\([^\\r\\n]*\\)${suffix}`)],
  ];
  for (const [kind, pattern] of candidates) {
    const match = pattern.exec(line);
    if (match) return { name: match[1]!, kind };
  }
  return undefined;
}

function exactSingleArgumentCall(line: string, binding: string): boolean {
  const value = escapeRegex(binding);
  return new RegExp(
    `^\\s*(?:(?:return|await|void)\\s+)?[A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)*\\s*\\(\\s*${value}\\s*\\)\\s*;?\\s*$`,
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

async function readSafeJavascriptFiles(
  rootPath: string,
  graph: CallGraph,
  options: KoaRequestInputForwardingOptions,
): Promise<Map<string, string[]>> {
  const root = resolve(rootPath);
  const maxFiles = boundedInteger(options.maxFiles, DEFAULT_MAX_FILES, MAX_FILES, "Koa request-forwarding maxFiles");
  const maxSourceBytes = boundedInteger(
    options.maxSourceBytes,
    DEFAULT_MAX_SOURCE_BYTES,
    MAX_SOURCE_BYTES,
    "Koa request-forwarding maxSourceBytes",
  );
  const extensions = [".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"];
  const paths = [...new Set(graph.nodes
    .filter((node) => extensions.some((extension) => node.path.toLowerCase().endsWith(extension)))
    .map((node) => normalizedPath(node.path)))].slice(0, maxFiles);
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

function isDefensibleKoaSink(
  sink: RouteSinkFlowContext["evidence"][number],
  files: ReadonlyMap<string, string[]>,
): boolean {
  if (sink.kind !== "database") return true;
  const line = files.get(comparisonPath(sink.path))?.[sink.line - 1] ?? "";
  return /\.\s*(?:query|execute|executemany|raw|rawQuery|createQueryRunner)\s*\(/i.test(line);
}

/**
 * Recognize one deliberately narrow Koa forwarding shape:
 *
 *   const value = ctx.query.term;
 *   await sink(value);
 *
 * The source must be an exact assignment from the resolved handler's first plain context parameter.
 * The local must have exactly one later occurrence in the handler, stay within maxForwardLines, and
 * be passed unchanged as the sole argument of one exact call. Reassignment, multiple use,
 * destructuring, transformations, aliasing, object spreading, middleware propagation and deeper
 * call chains fail closed. This is structural repository evidence, not a taint or runtime model.
 */
export async function buildKoaRouteRequestInputForwardingContexts(
  rootPath: string,
  routeFlows: readonly RouteSinkFlowContext[],
  graph: CallGraph,
  options: KoaRequestInputForwardingOptions = {},
): Promise<KoaRouteRequestInputForwardingContext[]> {
  const maxEvidence = boundedInteger(options.maxEvidence, DEFAULT_MAX_EVIDENCE, MAX_EVIDENCE, "Koa request-forwarding maxEvidence");
  const maxRoutes = boundedInteger(options.maxRoutes, DEFAULT_MAX_ROUTES, MAX_ROUTES, "Koa request-forwarding maxRoutes");
  const maxForwardLines = boundedInteger(
    options.maxForwardLines,
    DEFAULT_MAX_FORWARD_LINES,
    MAX_FORWARD_LINES,
    "Koa request-forwarding maxForwardLines",
  );
  const files = await readSafeJavascriptFiles(rootPath, graph, options);
  const output: KoaRouteRequestInputForwardingContext[] = [];

  for (const routeFlow of routeFlows.slice(0, maxRoutes)) {
    if (routeFlow.route.frameworkHint !== "Koa router") continue;
    const node = graph.nodes.find((candidate) => candidate.id === routeFlow.handler.id);
    if (!node || (node.kind !== "function" && node.kind !== "arrow-function")) continue;
    const lines = files.get(comparisonPath(node.path));
    if (!lines) continue;
    const contextName = handlerContextParameter(node, lines);
    if (!contextName) continue;
    const evidence: KoaRequestInputForwardingEvidence[] = [];

    for (let sourceLine = node.line; sourceLine <= node.endLine && evidence.length < maxEvidence; sourceLine += 1) {
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
        if (!isDefensibleKoaSink(sink, files)) continue;
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

    if (evidence.length === 0) continue;
    output.push({
      route: routeFlow.route,
      resolution: routeFlow.resolution,
      handler: routeFlow.handler,
      evidence,
      sourceKinds: [...new Set(evidence.map((item) => item.source.kind))],
      sinkKinds: [...new Set(evidence.map((item) => item.sink.kind))],
      interpretation: "structural-koa-context-source-single-use-local-call-sink-evidence-only",
    });
  }
  return output;
}

/** Return aggregate structural evidence for an exact finding sink line without request keys/values. */
export function findingKoaRequestInputForwardingEvidence(
  contexts: readonly KoaRouteRequestInputForwardingContext[],
  path: string,
  line: number | undefined,
  maxRoutes = 3,
): FindingKoaRequestInputForwardingEvidence[] {
  if (!Number.isSafeInteger(line) || (line ?? 0) <= 0) return [];
  const normalized = comparisonPath(path);
  const limit = Math.max(1, Math.min(10, maxRoutes));
  const output: FindingKoaRequestInputForwardingEvidence[] = [];
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
        interpretation: "structural-koa-context-source-single-use-local-call-sink-evidence-only",
      });
      if (output.length >= limit) return output;
    }
  }
  return output;
}
