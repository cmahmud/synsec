import { lstat, readFile } from "node:fs/promises";
import { extname, isAbsolute, relative, resolve, sep } from "node:path";
import type { IndexFileInput, RouteSignal, SinkSignal } from "./analysis.js";
import type { CallGraph, CallGraphNode } from "./call-graph.js";
import type { ImportCallLinkGraph } from "./import-call-links.js";
import type { RequestInputSignal } from "./request-input-flow.js";
import type { RouteSinkFlowContext } from "./route-sink-flow.js";

const MAX_SOURCE_BYTES = 512_000;
const MAX_FILES = 5_000;
const DEFAULT_MAX_FORWARD_LINES = 12;
const MAX_FORWARD_LINES = 40;
const MAX_EVIDENCE = 50;
const jsExtensions = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"]);

export interface RequestInputReturnFlowEvidence {
  source: {
    path: string;
    line: number;
    kind: RequestInputSignal["kind"];
    access: string;
    functionId: string;
    functionName: string;
  };
  bridge: {
    callerFunctionId: string;
    callerFunctionName: string;
    callerPath: string;
    helperCallLine: number;
    forwardingCallLine: number;
    routeDepth: number;
  };
  sink: {
    path: string;
    line: number;
    kind: SinkSignal["kind"];
    functionId: string;
    functionName: string;
  };
  /** Directed call distance from the forwarding call to the sink-owning function. */
  callDistance: number;
  callScope: "same-file" | "same-file-and-explicit-imports";
}

export interface RouteRequestInputReturnFlowContext {
  route: RouteSignal;
  resolution: RouteSinkFlowContext["resolution"];
  handler: RouteSinkFlowContext["handler"];
  evidence: RequestInputReturnFlowEvidence[];
  sourceKinds: RequestInputSignal["kind"][];
  sinkKinds: SinkSignal["kind"][];
  /**
   * Evidence requires an exact direct request access returned from one helper, an exact resolved
   * helper call whose return is bound with const, and exactly one unchanged direct-argument use
   * before a bounded downstream sink. It is not general taint, runtime reachability, attacker
   * control, sanitization analysis, or exploitability evidence.
   */
  interpretation: "structural-request-source-return-binding-call-sink-evidence-only";
}

export interface FindingRequestInputReturnFlowEvidence {
  method: string;
  route: string;
  frameworkHint?: string;
  resolution: RouteSinkFlowContext["resolution"];
  handler: string;
  sourceKind: RequestInputSignal["kind"];
  sourceFunction: string;
  sinkKind: SinkSignal["kind"];
  sinkFunction: string;
  callDistance: number;
  callScope: RequestInputReturnFlowEvidence["callScope"];
  interpretation: "structural-request-source-return-binding-call-sink-evidence-only";
}

export interface RequestInputReturnFlowOptions {
  maxForwardLines?: number;
  maxEvidence?: number;
  maxRoutes?: number;
  maxCallNodes?: number;
}

interface GraphEdges {
  targets: Map<string, string[]>;
  imported: Set<string>;
}

interface HelperBridge {
  caller: CallGraphNode;
  helper: CallGraphNode;
  helperCallLine: number;
  binding: string;
  forwardingCallLine: number;
  forwardingTarget: string;
  helperCallImported: boolean;
  forwardingCallImported: boolean;
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

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function boundedForwardLines(value: number | undefined): number {
  const resolved = value ?? DEFAULT_MAX_FORWARD_LINES;
  if (!Number.isSafeInteger(resolved) || resolved < 1 || resolved > MAX_FORWARD_LINES) {
    throw new Error(`Request-input return-flow maxForwardLines must be an integer between 1 and ${MAX_FORWARD_LINES}.`);
  }
  return resolved;
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
  return content === undefined || content.includes("\u0000") ? undefined : content;
}

function owningFunction(graph: CallGraph, path: string, line: number): CallGraphNode | undefined {
  const normalized = comparisonPath(path);
  const matches = graph.nodes.filter(
    (node) => comparisonPath(node.path) === normalized && line >= node.line && line <= node.endLine,
  );
  return matches.length === 1 ? matches[0] : undefined;
}

function graphEdges(graph: CallGraph, imports: ImportCallLinkGraph): GraphEdges {
  const buckets = new Map<string, Set<string>>();
  const imported = new Set<string>();
  const add = (from: string, target: string): void => {
    const bucket = buckets.get(from) ?? new Set<string>();
    bucket.add(target);
    buckets.set(from, bucket);
  };
  for (const edge of graph.edges) if (edge.target) add(edge.from, edge.target);
  for (const link of imports.links) {
    add(link.from, link.target);
    imported.add(`${link.from}\u0000${link.target}`);
  }
  return {
    targets: new Map([...buckets.entries()].map(([key, value]) => [key, [...value].sort()])),
    imported,
  };
}

function shortestPath(
  start: string,
  target: string,
  edges: GraphEdges,
  maxDepth: number,
  maxNodes: number,
): { distance: number; usedImport: boolean } | undefined {
  if (start === target) return { distance: 0, usedImport: false };
  const queue: Array<{ id: string; depth: number; usedImport: boolean }> = [{ id: start, depth: 0, usedImport: false }];
  const bestDepth = new Map<string, number>([[start, 0]]);
  let examined = 0;
  while (queue.length > 0 && examined < maxNodes) {
    const current = queue.shift();
    if (!current || current.depth >= maxDepth) continue;
    examined += 1;
    for (const next of edges.targets.get(current.id) ?? []) {
      const depth = current.depth + 1;
      const usedImport = current.usedImport || edges.imported.has(`${current.id}\u0000${next}`);
      if (next === target) return { distance: depth, usedImport };
      const prior = bestDepth.get(next);
      if (prior !== undefined && prior <= depth) continue;
      bestDepth.set(next, depth);
      queue.push({ id: next, depth, usedImport });
    }
  }
  return undefined;
}

function helperHasExactSingleReturn(
  source: string,
  node: CallGraphNode,
  signal: RequestInputSignal,
): boolean {
  const lines = source.split(/\r?\n/);
  const body = lines.slice(node.line - 1, node.endLine);
  const returnLines: number[] = [];
  for (let index = 0; index < body.length; index += 1) {
    if (/^\s*return\b/.test(body[index] ?? "")) returnLines.push(node.line + index);
  }
  if (returnLines.length !== 1 || returnLines[0] !== signal.line) return false;
  const line = lines[signal.line - 1] ?? "";
  if (signal.frameworkFamily !== "node-request") return false;
  return /^\s*return\s+(?:req|request)\.(?:body|query|params|headers|cookies|files?)(?:\.[A-Za-z_$][\w$]*|\[["'][^"'\r\n]{1,64}["']\])*\s*;?\s*$/.test(line);
}

function resolvedCallsTo(
  graph: CallGraph,
  imports: ImportCallLinkGraph,
  helperId: string,
): Array<{ from: string; line: number; callee: string; imported: boolean }> {
  const output: Array<{ from: string; line: number; callee: string; imported: boolean }> = [];
  for (const edge of graph.edges) {
    if (edge.target === helperId) output.push({ from: edge.from, line: edge.line, callee: edge.callee, imported: false });
  }
  for (const link of imports.links) {
    if (link.target === helperId) output.push({ from: link.from, line: link.line, callee: link.callee, imported: true });
  }
  return output.sort((a, b) => a.from.localeCompare(b.from) || a.line - b.line || a.callee.localeCompare(b.callee));
}

function uniqueResolvedTargetAtLine(
  graph: CallGraph,
  imports: ImportCallLinkGraph,
  callerId: string,
  line: number,
  callee: string,
): { target: string; imported: boolean } | undefined {
  const matches: Array<{ target: string; imported: boolean }> = [];
  for (const edge of graph.edges) {
    if (edge.from === callerId && edge.line === line && edge.callee === callee && edge.target) {
      matches.push({ target: edge.target, imported: false });
    }
  }
  for (const link of imports.links) {
    if (link.from === callerId && link.line === line && link.callee === callee) {
      matches.push({ target: link.target, imported: true });
    }
  }
  const uniqueTargets = [...new Set(matches.map((match) => match.target))];
  if (uniqueTargets.length !== 1) return undefined;
  const target = uniqueTargets[0];
  if (!target) return undefined;
  return { target, imported: matches.some((match) => match.target === target && match.imported) };
}

function parseHelperBinding(line: string, callee: string): { binding: string } | undefined {
  const escaped = escapeRegExp(callee);
  const match = line.match(new RegExp(`^\\s*const\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*${escaped}\\(\\s*[A-Za-z_$][\\w$]*\\s*\\)\\s*;?\\s*$`));
  return match?.[1] ? { binding: match[1] } : undefined;
}

function findSingleForwardUse(
  lines: readonly string[],
  caller: CallGraphNode,
  helperCallLine: number,
  binding: string,
  maxForwardLines: number,
): { line: number; callee: string } | undefined {
  const escapedBinding = escapeRegExp(binding);
  const occurrence = new RegExp(`\\b${escapedBinding}\\b`, "g");
  const uses: Array<{ line: number; text: string }> = [];
  for (let line = helperCallLine + 1; line <= caller.endLine; line += 1) {
    const text = lines[line - 1] ?? "";
    occurrence.lastIndex = 0;
    let count = 0;
    for (let match = occurrence.exec(text); match; match = occurrence.exec(text)) count += 1;
    for (let index = 0; index < count; index += 1) uses.push({ line, text });
    if (uses.length > 1) return undefined;
  }
  if (uses.length !== 1) return undefined;
  const use = uses[0];
  if (!use || use.line - helperCallLine > maxForwardLines) return undefined;
  const call = use.text.match(new RegExp(`^\\s*([A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)?)\\s*\\(\\s*${escapedBinding}\\s*\\)\\s*;?\\s*$`));
  return call?.[1] ? { line: use.line, callee: call[1] } : undefined;
}

async function bridgeCandidates(
  root: string,
  files: readonly IndexFileInput[],
  signals: readonly RequestInputSignal[],
  graph: CallGraph,
  imports: ImportCallLinkGraph,
  maxForwardLines: number,
): Promise<HelperBridge[]> {
  const fileByPath = new Map(files.slice(0, MAX_FILES).map((file) => [comparisonPath(file.path), file]));
  const sourceCache = new Map<string, string | undefined>();
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
  const getSource = async (path: string): Promise<string | undefined> => {
    const key = comparisonPath(path);
    if (sourceCache.has(key)) return sourceCache.get(key);
    const file = fileByPath.get(key);
    const source = file && jsExtensions.has(extname(file.path).toLowerCase()) ? await readBoundedSource(root, file) : undefined;
    sourceCache.set(key, source);
    return source;
  };
  const output: HelperBridge[] = [];

  for (const signal of signals) {
    if (signal.frameworkFamily !== "node-request") continue;
    const helper = owningFunction(graph, signal.path, signal.line);
    if (!helper || helper.kind === "python-function") continue;
    const helperSource = await getSource(helper.path);
    if (!helperSource || !helperHasExactSingleReturn(helperSource, helper, signal)) continue;

    for (const inbound of resolvedCallsTo(graph, imports, helper.id)) {
      const caller = nodeById.get(inbound.from);
      if (!caller || caller.kind === "python-function") continue;
      const callerSource = await getSource(caller.path);
      if (!callerSource) continue;
      const lines = callerSource.split(/\r?\n/);
      const binding = parseHelperBinding(lines[inbound.line - 1] ?? "", inbound.callee);
      if (!binding) continue;
      const forward = findSingleForwardUse(lines, caller, inbound.line, binding.binding, maxForwardLines);
      if (!forward) continue;
      const target = uniqueResolvedTargetAtLine(graph, imports, caller.id, forward.line, forward.callee);
      if (!target || target.target === helper.id) continue;
      output.push({
        caller,
        helper,
        helperCallLine: inbound.line,
        binding: binding.binding,
        forwardingCallLine: forward.line,
        forwardingTarget: target.target,
        helperCallImported: inbound.imported,
        forwardingCallImported: target.imported,
      });
    }
  }

  return output;
}

/**
 * Build the deliberately narrow request-helper-return -> immutable caller binding -> downstream call
 * evidence layer. It accepts only JS/TS helpers with exactly one `return req.<source>` statement,
 * exact resolved one-argument helper calls assigned to `const`, and one unchanged direct-argument
 * use of that binding. Any transformation, destructuring, mutation, multiple use, unresolved call,
 * non-direct return, or ambiguous function ownership is omitted rather than inferred.
 */
export async function repositoryRouteRequestInputReturnFlowContexts(
  rootPath: string,
  files: readonly IndexFileInput[],
  signals: readonly RequestInputSignal[],
  routeFlows: readonly RouteSinkFlowContext[],
  graph: CallGraph,
  imports: ImportCallLinkGraph,
  options: RequestInputReturnFlowOptions = {},
): Promise<RouteRequestInputReturnFlowContext[]> {
  const root = resolve(rootPath);
  const maxForwardLines = boundedForwardLines(options.maxForwardLines);
  const maxEvidence = Math.max(1, Math.min(MAX_EVIDENCE, options.maxEvidence ?? 12));
  const maxRoutes = Math.max(0, Math.min(5_000, options.maxRoutes ?? 1_000));
  const maxCallNodes = Math.max(1, Math.min(1_000, options.maxCallNodes ?? 100));
  const bridges = await bridgeCandidates(root, files, signals, graph, imports, maxForwardLines);
  const edges = graphEdges(graph, imports);
  const sourceByFunction = new Map<string, RequestInputSignal[]>();
  for (const signal of signals) {
    const node = owningFunction(graph, signal.path, signal.line);
    if (!node) continue;
    const bucket = sourceByFunction.get(node.id) ?? [];
    bucket.push(signal);
    sourceByFunction.set(node.id, bucket);
  }
  const output: RouteRequestInputReturnFlowContext[] = [];

  for (const routeFlow of routeFlows.slice(0, maxRoutes)) {
    const evidence: RequestInputReturnFlowEvidence[] = [];
    const routeMaxDepth = Math.max(0, routeFlow.maxDepth);
    for (const bridge of bridges) {
      if (evidence.length >= maxEvidence) break;
      const routeToCaller = shortestPath(routeFlow.handler.id, bridge.caller.id, edges, routeMaxDepth, maxCallNodes);
      if (!routeToCaller) continue;
      const callerToHelper = uniqueResolvedTargetAtLine(graph, imports, bridge.caller.id, bridge.helperCallLine,
        (graph.edges.find((edge) => edge.from === bridge.caller.id && edge.line === bridge.helperCallLine && edge.target === bridge.helper.id)?.callee)
        ?? (imports.links.find((link) => link.from === bridge.caller.id && link.line === bridge.helperCallLine && link.target === bridge.helper.id)?.callee)
        ?? "");
      if (!callerToHelper || callerToHelper.target !== bridge.helper.id) continue;
      if (routeToCaller.distance + 1 > routeMaxDepth) continue;

      const sources = sourceByFunction.get(bridge.helper.id) ?? [];
      for (const source of sources) {
        if (evidence.length >= maxEvidence) break;
        const helperSourceFile = files.find((file) => comparisonPath(file.path) === comparisonPath(bridge.helper.path));
        if (!helperSourceFile) continue;
        const helperSource = await readBoundedSource(root, helperSourceFile);
        if (!helperSource || !helperHasExactSingleReturn(helperSource, bridge.helper, source)) continue;

        for (const sink of routeFlow.evidence) {
          if (evidence.length >= maxEvidence) break;
          const downstream = shortestPath(bridge.forwardingTarget, sink.functionId, edges, routeMaxDepth, maxCallNodes);
          if (!downstream) continue;
          const callDistance = 1 + downstream.distance;
          const usedImport = routeToCaller.usedImport
            || bridge.helperCallImported
            || bridge.forwardingCallImported
            || downstream.usedImport;
          evidence.push({
            source: {
              path: source.path,
              line: source.line,
              kind: source.kind,
              access: source.access,
              functionId: bridge.helper.id,
              functionName: bridge.helper.name,
            },
            bridge: {
              callerFunctionId: bridge.caller.id,
              callerFunctionName: bridge.caller.name,
              callerPath: bridge.caller.path,
              helperCallLine: bridge.helperCallLine,
              forwardingCallLine: bridge.forwardingCallLine,
              routeDepth: routeToCaller.distance,
            },
            sink: {
              path: sink.path,
              line: sink.line,
              kind: sink.kind,
              functionId: sink.functionId,
              functionName: sink.functionName,
            },
            callDistance,
            callScope: usedImport ? "same-file-and-explicit-imports" : "same-file",
          });
        }
      }
    }
    if (evidence.length === 0) continue;
    evidence.sort((a, b) => a.bridge.routeDepth - b.bridge.routeDepth
      || a.callDistance - b.callDistance
      || a.source.path.localeCompare(b.source.path)
      || a.source.line - b.source.line
      || a.sink.path.localeCompare(b.sink.path)
      || a.sink.line - b.sink.line);
    output.push({
      route: routeFlow.route,
      resolution: routeFlow.resolution,
      handler: routeFlow.handler,
      evidence,
      sourceKinds: [...new Set(evidence.map((item) => item.source.kind))],
      sinkKinds: [...new Set(evidence.map((item) => item.sink.kind))],
      interpretation: "structural-request-source-return-binding-call-sink-evidence-only",
    });
  }
  return output;
}

/** Return sanitized structural evidence only when a finding exactly matches the linked sink line. */
export function findingRequestInputReturnFlowEvidence(
  contexts: readonly RouteRequestInputReturnFlowContext[],
  path: string,
  line: number | undefined,
  maxRoutes = 3,
): FindingRequestInputReturnFlowEvidence[] {
  if (!Number.isSafeInteger(line) || (line ?? 0) <= 0) return [];
  const normalized = comparisonPath(path);
  const limit = Math.max(1, Math.min(10, maxRoutes));
  const output: FindingRequestInputReturnFlowEvidence[] = [];
  for (const context of contexts) {
    const match = context.evidence.find((item) => comparisonPath(item.sink.path) === normalized && item.sink.line === line);
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
      callScope: match.callScope,
      interpretation: "structural-request-source-return-binding-call-sink-evidence-only",
    });
    if (output.length >= limit) break;
  }
  return output;
}
