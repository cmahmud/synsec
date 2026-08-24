import { lstat, readFile } from "node:fs/promises";
import { extname, isAbsolute, relative, resolve, sep } from "node:path";
import type { IndexFileInput, RepositoryIndex, RouteSignal, SinkSignal } from "./analysis.js";
import type { CallGraph, CallGraphNode } from "./call-graph.js";
import type { ImportCallLinkGraph } from "./import-call-links.js";
import type { RouteEntrypoint, RouteEntrypointResolution } from "./route-entrypoints.js";

export type RequestInputKind = "body" | "query" | "path" | "header" | "cookie" | "file";

export interface RequestInputSignal {
  path: string;
  line: number;
  kind: RequestInputKind;
  frameworkFamily: "node-request" | "python-request";
  /** Sanitized structural access category; source text and values are intentionally excluded. */
  access: string;
}

export interface RequestInputFlowEvidence {
  source: {
    path: string;
    line: number;
    kind: RequestInputKind;
    frameworkFamily: RequestInputSignal["frameworkFamily"];
    access: string;
    functionId: string;
    functionName: string;
    routeDepth: number;
  };
  sink: {
    path: string;
    line: number;
    kind: SinkSignal["kind"];
    functionId: string;
    functionName: string;
    routeDepth: number;
  };
  /** Directed lexical/import-call distance from the source-owning function to the sink-owning function. */
  callDistance: number;
}

export interface RouteRequestInputFlowContext {
  route: RouteSignal;
  resolution: Exclude<RouteEntrypointResolution, "unresolved">;
  handler: {
    id: string;
    name: string;
    path: string;
    line: number;
    endLine: number;
  };
  evidence: RequestInputFlowEvidence[];
  sourceKinds: RequestInputKind[];
  sinkKinds: SinkSignal["kind"][];
  callScope: "same-file" | "same-file-and-explicit-imports";
  /**
   * This proves only a bounded structural request-access -> directed call path -> sink relationship.
   * It is not variable-level taint, runtime reachability, attacker control, or exploitability evidence.
   */
  interpretation: "structural-request-source-call-sink-evidence-only";
}

export interface FindingRequestInputFlowEvidence {
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
  callScope: RouteRequestInputFlowContext["callScope"];
  interpretation: "structural-request-source-call-sink-evidence-only";
}

export interface RequestInputFlowOptions {
  maxSignals?: number;
  maxEvidence?: number;
  maxRoutes?: number;
  maxCallNodes?: number;
  importCallLinks?: ImportCallLinkGraph;
}

const MAX_SOURCE_BYTES = 512_000;
const MAX_FILES = 5_000;
const MAX_SIGNALS = 10_000;
const MAX_SIGNALS_PER_FILE = 500;
const jsExtensions = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"]);

function normalizedPath(value: string): string {
  return value.replaceAll("\\", "/").replace(/^\.\//, "");
}

function normalizedComparisonPath(value: string): string {
  return normalizedPath(value).replace(/^\//, "").toLowerCase();
}

function insideRoot(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

async function readBoundedSource(root: string, file: IndexFileInput): Promise<string | undefined> {
  if (file.size > MAX_SOURCE_BYTES) return undefined;
  const path = normalizedPath(file.path);
  if (!path || path.includes("\0") || path.startsWith("../") || isAbsolute(file.path)) return undefined;
  const absolute = resolve(root, path);
  if (!insideRoot(root, absolute)) return undefined;
  const info = await lstat(absolute).catch(() => undefined);
  if (!info?.isFile() || info.isSymbolicLink() || info.size > MAX_SOURCE_BYTES) return undefined;
  const content = await readFile(absolute, "utf8").catch(() => undefined);
  if (content === undefined || content.includes("\u0000")) return undefined;
  return content;
}

function requestKind(member: string): RequestInputKind | undefined {
  const normalized = member.toLowerCase();
  if (["body", "json", "form", "data", "values"].includes(normalized)) return "body";
  if (["query", "args", "get"].includes(normalized)) return "query";
  if (["params", "path_params"].includes(normalized)) return "path";
  if (["header", "headers"].includes(normalized)) return "header";
  if (["cookie", "cookies"].includes(normalized)) return "cookie";
  if (["file", "files"].includes(normalized)) return "file";
  return undefined;
}

function nodeRequestAccesses(line: string): Array<{ kind: RequestInputKind; access: string }> {
  const output: Array<{ kind: RequestInputKind; access: string }> = [];
  const direct = /\b(?:req|request)\.(body|query|params|headers|cookies|files?)\b/gi;
  for (let match = direct.exec(line); match; match = direct.exec(line)) {
    const member = match[1];
    const kind = member ? requestKind(member) : undefined;
    if (kind) output.push({ kind, access: `request.${member?.toLowerCase()}` });
  }

  const koa = /\bctx\.(?:request\.)?(body|query|params|headers|cookies)\b/gi;
  for (let match = koa.exec(line); match; match = koa.exec(line)) {
    const member = match[1];
    const kind = member ? requestKind(member) : undefined;
    if (kind) output.push({ kind, access: `ctx.request.${member?.toLowerCase()}` });
  }

  const hono = /\b[A-Za-z_$][\w$]*\.req\.(json|query|param|header|cookie)\s*\(/gi;
  for (let match = hono.exec(line); match; match = hono.exec(line)) {
    const member = match[1]?.toLowerCase();
    const normalizedMember = member === "param" ? "params" : member;
    const kind = normalizedMember ? requestKind(normalizedMember) : undefined;
    if (kind) output.push({ kind, access: `context.req.${member}` });
  }
  return output;
}

function pythonRequestAccesses(line: string): Array<{ kind: RequestInputKind; access: string }> {
  const output: Array<{ kind: RequestInputKind; access: string }> = [];
  const flask = /\brequest\.(args|form|json|values|headers|cookies|files|data)\b/g;
  for (let match = flask.exec(line); match; match = flask.exec(line)) {
    const member = match[1];
    const kind = member ? requestKind(member) : undefined;
    if (kind) output.push({ kind, access: `request.${member}` });
  }
  const getJson = /\brequest\.get_json\s*\(/g;
  if (getJson.test(line)) output.push({ kind: "body", access: "request.get_json" });

  const django = /\brequest\.(GET|POST|body|headers|COOKIES|FILES)\b/g;
  for (let match = django.exec(line); match; match = django.exec(line)) {
    const member = match[1];
    let kind: RequestInputKind | undefined;
    if (member === "GET") kind = "query";
    else if (member === "POST" || member === "body") kind = "body";
    else kind = member ? requestKind(member) : undefined;
    if (kind) output.push({ kind, access: `request.${member}` });
  }
  return output;
}

/**
 * Collect explicit request-access expressions only. Function parameters, variable names, decorators,
 * route declarations, and auth-looking tokens are not inferred as request-controlled input.
 */
export async function collectRequestInputSignals(
  rootPath: string,
  files: readonly IndexFileInput[],
  options: Pick<RequestInputFlowOptions, "maxSignals"> = {},
): Promise<RequestInputSignal[]> {
  const root = resolve(rootPath);
  const maxSignals = Math.max(1, Math.min(MAX_SIGNALS, options.maxSignals ?? MAX_SIGNALS));
  const output: RequestInputSignal[] = [];

  for (const file of files.slice(0, MAX_FILES)) {
    if (output.length >= maxSignals) break;
    const extension = extname(file.path).toLowerCase();
    const family = jsExtensions.has(extension) ? "node-request" : extension === ".py" ? "python-request" : undefined;
    if (!family) continue;
    const content = await readBoundedSource(root, file);
    if (!content) continue;
    const lines = content.split(/\r?\n/);
    let fileSignals = 0;
    for (let index = 0; index < lines.length && fileSignals < MAX_SIGNALS_PER_FILE && output.length < maxSignals; index += 1) {
      const accesses = family === "node-request" ? nodeRequestAccesses(lines[index] ?? "") : pythonRequestAccesses(lines[index] ?? "");
      for (const access of accesses) {
        output.push({
          path: normalizedPath(file.path),
          line: index + 1,
          kind: access.kind,
          frameworkFamily: family,
          access: access.access,
        });
        fileSignals += 1;
        if (fileSignals >= MAX_SIGNALS_PER_FILE || output.length >= maxSignals) break;
      }
    }
  }

  return output;
}

function owningFunction(graph: CallGraph, path: string, line: number): CallGraphNode | undefined {
  const normalized = normalizedComparisonPath(path);
  const candidates = graph.nodes.filter(
    (node) => normalizedComparisonPath(node.path) === normalized && line >= node.line && line <= node.endLine,
  );
  return candidates.length === 1 ? candidates[0] : undefined;
}

function adjacency(
  graph: CallGraph,
  importCallLinks: ImportCallLinkGraph | undefined,
): { targets: Map<string, string[]>; importedEdges: Set<string> } {
  const targets = new Map<string, Set<string>>();
  const importedEdges = new Set<string>();
  const add = (from: string, to: string): void => {
    const bucket = targets.get(from) ?? new Set<string>();
    bucket.add(to);
    targets.set(from, bucket);
  };
  for (const edge of graph.edges) if (edge.target) add(edge.from, edge.target);
  for (const link of importCallLinks?.links ?? []) {
    add(link.from, link.target);
    importedEdges.add(`${link.from}\u0000${link.target}`);
  }
  return {
    targets: new Map([...targets.entries()].map(([from, values]) => [from, [...values].sort()])),
    importedEdges,
  };
}

function reachableFrom(
  start: string,
  targets: ReadonlyMap<string, readonly string[]>,
  maxDepth: number,
  maxNodes: number,
  allowed?: ReadonlySet<string>,
): Map<string, number> {
  const depths = new Map<string, number>([[start, 0]]);
  const queue: Array<{ id: string; depth: number }> = [{ id: start, depth: 0 }];
  while (queue.length > 0 && depths.size < maxNodes) {
    const current = queue.shift();
    if (!current || current.depth >= maxDepth) continue;
    for (const target of targets.get(current.id) ?? []) {
      if (allowed && !allowed.has(target)) continue;
      if (depths.has(target)) continue;
      const depth = current.depth + 1;
      depths.set(target, depth);
      queue.push({ id: target, depth });
      if (depths.size >= maxNodes) break;
    }
  }
  return depths;
}

function usedImportOnShortestPath(
  start: string,
  target: string,
  targets: ReadonlyMap<string, readonly string[]>,
  importedEdges: ReadonlySet<string>,
  maxDepth: number,
  allowed: ReadonlySet<string>,
): boolean {
  if (start === target) return false;
  const queue: Array<{ id: string; depth: number; usedImport: boolean }> = [{ id: start, depth: 0, usedImport: false }];
  const seen = new Set<string>([start]);
  while (queue.length > 0) {
    const current = queue.shift();
    if (!current || current.depth >= maxDepth) continue;
    for (const next of targets.get(current.id) ?? []) {
      if (!allowed.has(next) || seen.has(next)) continue;
      const usedImport = current.usedImport || importedEdges.has(`${current.id}\u0000${next}`);
      if (next === target) return usedImport;
      seen.add(next);
      queue.push({ id: next, depth: current.depth + 1, usedImport });
    }
  }
  return false;
}

/**
 * Build bounded directional request-source -> call graph -> sink evidence for one resolved route.
 * A source/sink must each belong to exactly one lexical function. The sink-owning function must be
 * reachable from the source-owning function through resolved same-file calls or explicit unique
 * import-call links, and all nodes must remain within the route's bounded call neighborhood.
 */
export function routeRequestInputFlowContext(
  index: RepositoryIndex,
  requestInputs: readonly RequestInputSignal[],
  entrypoint: RouteEntrypoint,
  graph: CallGraph,
  options: RequestInputFlowOptions = {},
): RouteRequestInputFlowContext | undefined {
  if (!entrypoint.handler || entrypoint.resolution === "unresolved") return undefined;
  const maxEvidence = Math.max(1, Math.min(50, options.maxEvidence ?? 12));
  const maxNodes = Math.max(1, Math.min(1_000, options.maxCallNodes ?? 100));
  const maxDepth = Math.max(0, Math.min(12, entrypoint.calls?.maxDepth ?? 0));
  const graphEdges = adjacency(graph, options.importCallLinks);
  const routeDepths = reachableFrom(entrypoint.handler.id, graphEdges.targets, maxDepth, maxNodes);
  const routeNodes = new Set(routeDepths.keys());
  if (routeNodes.size === 0) return undefined;

  const sources = requestInputs.flatMap((signal) => {
    const node = owningFunction(graph, signal.path, signal.line);
    const routeDepth = node ? routeDepths.get(node.id) : undefined;
    return node && routeDepth !== undefined ? [{ signal, node, routeDepth }] : [];
  });
  if (sources.length === 0) return undefined;

  const sinks = index.sinks.flatMap((signal) => {
    const node = owningFunction(graph, signal.path, signal.line);
    const routeDepth = node ? routeDepths.get(node.id) : undefined;
    return node && routeDepth !== undefined ? [{ signal, node, routeDepth }] : [];
  });
  if (sinks.length === 0) return undefined;

  const evidence: RequestInputFlowEvidence[] = [];
  let usedImport = false;
  for (const source of sources) {
    const downstream = reachableFrom(source.node.id, graphEdges.targets, maxDepth, maxNodes, routeNodes);
    for (const sink of sinks) {
      const callDistance = downstream.get(sink.node.id);
      if (callDistance === undefined) continue;
      usedImport = usedImport || usedImportOnShortestPath(
        source.node.id,
        sink.node.id,
        graphEdges.targets,
        graphEdges.importedEdges,
        maxDepth,
        routeNodes,
      );
      evidence.push({
        source: {
          path: source.signal.path,
          line: source.signal.line,
          kind: source.signal.kind,
          frameworkFamily: source.signal.frameworkFamily,
          access: source.signal.access,
          functionId: source.node.id,
          functionName: source.node.name,
          routeDepth: source.routeDepth,
        },
        sink: {
          path: sink.signal.path,
          line: sink.signal.line,
          kind: sink.signal.kind,
          functionId: sink.node.id,
          functionName: sink.node.name,
          routeDepth: sink.routeDepth,
        },
        callDistance,
      });
      if (evidence.length >= maxEvidence) break;
    }
    if (evidence.length >= maxEvidence) break;
  }
  if (evidence.length === 0) return undefined;

  evidence.sort((a, b) =>
    a.callDistance - b.callDistance ||
    a.source.path.localeCompare(b.source.path) || a.source.line - b.source.line ||
    a.sink.path.localeCompare(b.sink.path) || a.sink.line - b.sink.line,
  );
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
    evidence: evidence.slice(0, maxEvidence),
    sourceKinds: [...new Set(evidence.map((item) => item.source.kind))],
    sinkKinds: [...new Set(evidence.map((item) => item.sink.kind))],
    callScope: usedImport ? "same-file-and-explicit-imports" : "same-file",
    interpretation: "structural-request-source-call-sink-evidence-only",
  };
}

export function repositoryRouteRequestInputFlowContexts(
  index: RepositoryIndex,
  requestInputs: readonly RequestInputSignal[],
  entrypoints: readonly RouteEntrypoint[],
  graph: CallGraph,
  options: RequestInputFlowOptions = {},
): RouteRequestInputFlowContext[] {
  const maxRoutes = Math.max(0, Math.min(5_000, options.maxRoutes ?? 1_000));
  const output: RouteRequestInputFlowContext[] = [];
  for (const entrypoint of entrypoints.slice(0, maxRoutes)) {
    const context = routeRequestInputFlowContext(index, requestInputs, entrypoint, graph, options);
    if (context) output.push(context);
  }
  return output;
}

/** Correlate only to an exact sink line already linked to an explicit request source by a directed call path. */
export function findingRequestInputFlowEvidence(
  contexts: readonly RouteRequestInputFlowContext[],
  path: string,
  line: number | undefined,
  maxRoutes = 3,
): FindingRequestInputFlowEvidence[] {
  if (!Number.isSafeInteger(line) || (line ?? 0) <= 0) return [];
  const normalized = normalizedComparisonPath(path);
  const limit = Math.max(1, Math.min(10, maxRoutes));
  const output: FindingRequestInputFlowEvidence[] = [];
  for (const context of contexts) {
    const match = context.evidence.find(
      (item) => normalizedComparisonPath(item.sink.path) === normalized && item.sink.line === line,
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
      interpretation: "structural-request-source-call-sink-evidence-only",
    });
    if (output.length >= limit) break;
  }
  return output;
}
