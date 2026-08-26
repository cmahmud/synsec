import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { SinkSignal } from "./analysis.js";
import type { CallGraph, CallGraphNode } from "./call-graph.js";
import type { RouteSinkFlowContext } from "./route-sink-flow.js";

export type KoaRequestInputKind = "body" | "query" | "path" | "header" | "cookie";

export interface KoaRequestInputEvidence {
  source: {
    path: string;
    line: number;
    kind: KoaRequestInputKind;
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

export interface KoaRouteRequestInputFlowContext {
  route: RouteSinkFlowContext["route"];
  resolution: RouteSinkFlowContext["resolution"];
  handler: RouteSinkFlowContext["handler"];
  evidence: KoaRequestInputEvidence[];
  sourceKinds: KoaRequestInputKind[];
  sinkKinds: SinkSignal["kind"][];
  interpretation: "structural-koa-context-source-direct-call-sink-evidence-only";
}

export interface FindingKoaRequestInputFlowEvidence {
  method: string;
  route: string;
  frameworkHint?: string;
  handler: string;
  sourceKind: KoaRequestInputKind;
  sourceFunction: string;
  sinkKind: SinkSignal["kind"];
  sinkFunction: string;
  callDistance: 0 | 1;
  interpretation: "structural-koa-context-source-direct-call-sink-evidence-only";
}

export interface KoaRequestInputFlowOptions {
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

function requestAccesses(line: string, contextName: string): Array<{ kind: KoaRequestInputKind; access: string }> {
  const escaped = contextName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const output: Array<{ kind: KoaRequestInputKind; access: string }> = [];
  const candidates: Array<[KoaRequestInputKind, string, RegExp]> = [
    ["body", "koa.Context.request.body", new RegExp(`\\b${escaped}\\.request\\.body\\b`)],
    ["query", "koa.Context.query", new RegExp(`\\b${escaped}\\.query\\b`)],
    ["query", "koa.Context.request.query", new RegExp(`\\b${escaped}\\.request\\.query\\b`)],
    ["path", "koa.Context.params", new RegExp(`\\b${escaped}\\.params\\b`)],
    ["header", "koa.Context.headers", new RegExp(`\\b${escaped}\\.headers\\b`)],
    ["header", "koa.Context.request.headers", new RegExp(`\\b${escaped}\\.request\\.headers\\b`)],
    ["header", "koa.Context.get", new RegExp(`\\b${escaped}\\.get\\s*\\(`)],
    ["cookie", "koa.Context.cookies.get", new RegExp(`\\b${escaped}\\.cookies\\.get\\s*\\(`)],
  ];
  for (const [kind, access, pattern] of candidates) {
    if (pattern.test(line)) output.push({ kind, access });
  }
  return output;
}

async function readSafeJavascriptFiles(
  rootPath: string,
  graph: CallGraph,
  options: KoaRequestInputFlowOptions,
): Promise<Map<string, string[]>> {
  const root = resolve(rootPath);
  const maxFiles = boundedInteger(options.maxFiles, DEFAULT_MAX_FILES, MAX_FILES, "Koa request-flow maxFiles");
  const maxSourceBytes = boundedInteger(
    options.maxSourceBytes,
    DEFAULT_MAX_SOURCE_BYTES,
    MAX_SOURCE_BYTES,
    "Koa request-flow maxSourceBytes",
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
  // The generic repository sink index intentionally treats bare query/execute-like calls as
  // database-looking lexical evidence. Koa directional flow is stricter: database correlation is
  // retained only for a member-qualified database-style call. This rejects local helpers named
  // execute/query and their function declarations instead of upgrading those lexical collisions.
  return /\.\s*(?:query|execute|executemany|raw|rawQuery|createQueryRunner)\s*\(/i.test(line);
}

/**
 * Build deliberately narrow Koa request-source evidence from routes produced by the strict Koa
 * router composer. Only the resolved route handler's first plain identifier parameter is treated as
 * the structural Koa context. A recognized access must occur on the exact sink line or on the same
 * line as one direct call-graph edge to the sink-owning function. `ctx.body` is intentionally not a
 * request source because Koa uses it as the response body. Generic bare execute/query calls are also
 * excluded from database flow unless the sink line is member-qualified. Locals, aliasing,
 * transformations, destructuring, middleware propagation, and deeper argument flow are excluded.
 */
export async function buildKoaRouteRequestInputFlowContexts(
  rootPath: string,
  routeFlows: readonly RouteSinkFlowContext[],
  graph: CallGraph,
  options: KoaRequestInputFlowOptions = {},
): Promise<KoaRouteRequestInputFlowContext[]> {
  const maxEvidence = boundedInteger(options.maxEvidence, DEFAULT_MAX_EVIDENCE, MAX_EVIDENCE, "Koa request-flow maxEvidence");
  const maxRoutes = boundedInteger(options.maxRoutes, DEFAULT_MAX_ROUTES, MAX_ROUTES, "Koa request-flow maxRoutes");
  const files = await readSafeJavascriptFiles(rootPath, graph, options);
  const output: KoaRouteRequestInputFlowContext[] = [];

  for (const routeFlow of routeFlows.slice(0, maxRoutes)) {
    if (routeFlow.route.frameworkHint !== "Koa router") continue;
    const node = graph.nodes.find((candidate) => candidate.id === routeFlow.handler.id);
    if (!node || (node.kind !== "function" && node.kind !== "arrow-function")) continue;
    const lines = files.get(comparisonPath(node.path));
    if (!lines) continue;
    const contextName = handlerContextParameter(node, lines);
    if (!contextName) continue;
    const evidence: KoaRequestInputEvidence[] = [];

    for (let lineNumber = node.line; lineNumber <= node.endLine && evidence.length < maxEvidence; lineNumber += 1) {
      const line = lines[lineNumber - 1] ?? "";
      const accesses = requestAccesses(line, contextName);
      if (accesses.length === 0) continue;
      const targets = new Set(directTargets(graph, node.id, lineNumber));

      for (const sink of routeFlow.evidence) {
        if (!isDefensibleKoaSink(sink, files)) continue;
        const sameLineSink = sink.functionId === node.id && sink.line === lineNumber;
        const distance: 0 | 1 | undefined = sameLineSink ? 0 : targets.has(sink.functionId) ? 1 : undefined;
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

    if (evidence.length === 0) continue;
    output.push({
      route: routeFlow.route,
      resolution: routeFlow.resolution,
      handler: routeFlow.handler,
      evidence,
      sourceKinds: [...new Set(evidence.map((item) => item.source.kind))],
      sinkKinds: [...new Set(evidence.map((item) => item.sink.kind))],
      interpretation: "structural-koa-context-source-direct-call-sink-evidence-only",
    });
  }
  return output;
}

/** Return only aggregate structural evidence for an exact finding sink line. */
export function findingKoaRequestInputFlowEvidence(
  contexts: readonly KoaRouteRequestInputFlowContext[],
  path: string,
  line: number | undefined,
  maxRoutes = 3,
): FindingKoaRequestInputFlowEvidence[] {
  if (!Number.isSafeInteger(line) || (line ?? 0) <= 0) return [];
  const normalized = comparisonPath(path);
  const limit = Math.max(1, Math.min(10, maxRoutes));
  const output: FindingKoaRequestInputFlowEvidence[] = [];
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
        interpretation: "structural-koa-context-source-direct-call-sink-evidence-only",
      });
      if (output.length >= limit) return output;
    }
  }
  return output;
}
