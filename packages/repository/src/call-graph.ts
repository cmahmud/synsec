import { readFile, stat } from "node:fs/promises";
import { extname, resolve } from "node:path";
import type { IndexFileInput } from "./analysis.js";

export type CallGraphNodeKind = "function" | "arrow-function" | "python-function";
export type CallResolution = "same-file-function" | "external-or-unresolved";

export interface CallGraphNode {
  id: string;
  path: string;
  name: string;
  line: number;
  endLine: number;
  kind: CallGraphNodeKind;
}

export interface CallGraphEdge {
  from: string;
  callee: string;
  line: number;
  target?: string;
  resolution: CallResolution;
}

export interface CallGraph {
  schemaVersion: 1;
  nodes: CallGraphNode[];
  edges: CallGraphEdge[];
  resolvedEdgeCount: number;
  unresolvedEdgeCount: number;
  skippedFiles: Array<{ path: string; reason: string }>;
  /** Regex/lexical evidence is useful for review prioritization, not proof of runtime reachability. */
  interpretation: "lexical-call-evidence-only";
}

export interface CallNeighborhood {
  root: string;
  maxDepth: number;
  callees: Array<{ id: string; depth: number }>;
  callers: Array<{ id: string; depth: number }>;
  interpretation: "lexical-call-evidence-only";
}

const MAX_SOURCE_BYTES = 512_000;
const MAX_FILES = 5_000;
const MAX_FUNCTIONS_PER_FILE = 500;
const MAX_CALLS_PER_FUNCTION = 500;
const jsExtensions = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"]);
const ignoredCalls = new Set([
  "if", "for", "while", "switch", "catch", "function", "return", "typeof", "new", "await", "import",
  "require", "super", "this", "console", "Math", "JSON", "Object", "Array", "String", "Number", "Boolean",
]);

interface ParsedFunction {
  node: CallGraphNode;
  bodyStart: number;
  bodyEnd: number;
}

function normalizedPath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.\//, "");
}

function nodeId(path: string, name: string, line: number): string {
  return `${normalizedPath(path)}:${name}:${line}`;
}

function braceDelta(line: string): number {
  let delta = 0;
  let quote: "'" | '"' | "`" | undefined;
  let escaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    const next = line[index + 1];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quote) {
      if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") {
      quote = char;
      continue;
    }
    if (char === "/" && next === "/") break;
    if (char === "{") delta += 1;
    else if (char === "}") delta -= 1;
  }
  return delta;
}

function parseJavascriptFunctions(path: string, content: string): ParsedFunction[] {
  const lines = content.split(/\r?\n/);
  const functions: ParsedFunction[] = [];
  let depth = 0;

  for (let index = 0; index < lines.length && functions.length < MAX_FUNCTIONS_PER_FILE; index += 1) {
    const line = lines[index] ?? "";
    const declaration = line.match(/\b(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/);
    const arrow = line.match(/\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>/);
    const name = declaration?.[1] ?? arrow?.[1];
    const delta = braceDelta(line);

    if (name) {
      const startDepth = depth;
      let runningDepth = depth + delta;
      let endIndex = index;
      const hasBlock = line.includes("{") || delta > 0;

      if (hasBlock) {
        for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
          runningDepth += braceDelta(lines[cursor] ?? "");
          endIndex = cursor;
          if (runningDepth <= startDepth) break;
        }
      }

      functions.push({
        node: {
          id: nodeId(path, name, index + 1),
          path: normalizedPath(path),
          name,
          line: index + 1,
          endLine: endIndex + 1,
          kind: declaration ? "function" : "arrow-function",
        },
        bodyStart: index,
        bodyEnd: endIndex,
      });
    }

    depth += delta;
  }
  return functions;
}

function leadingIndent(line: string): number {
  const prefix = line.match(/^[ \t]*/)?.[0] ?? "";
  return [...prefix].reduce((total, char) => total + (char === "\t" ? 4 : 1), 0);
}

function parsePythonFunctions(path: string, content: string): ParsedFunction[] {
  const lines = content.split(/\r?\n/);
  const functions: ParsedFunction[] = [];

  for (let index = 0; index < lines.length && functions.length < MAX_FUNCTIONS_PER_FILE; index += 1) {
    const line = lines[index] ?? "";
    const declaration = line.match(/^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/);
    const name = declaration?.[1];
    if (!name) continue;

    const indent = leadingIndent(line);
    let endIndex = index;
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      const candidate = lines[cursor] ?? "";
      if (!candidate.trim() || candidate.trimStart().startsWith("#")) {
        endIndex = cursor;
        continue;
      }
      if (leadingIndent(candidate) <= indent) break;
      endIndex = cursor;
    }

    functions.push({
      node: {
        id: nodeId(path, name, index + 1),
        path: normalizedPath(path),
        name,
        line: index + 1,
        endLine: endIndex + 1,
        kind: "python-function",
      },
      bodyStart: index,
      bodyEnd: endIndex,
    });
  }
  return functions;
}

function collectCalls(lines: readonly string[], fn: ParsedFunction): Array<{ callee: string; line: number; direct: boolean }> {
  const calls: Array<{ callee: string; line: number; direct: boolean }> = [];
  const regex = /\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\(/g;

  for (let index = fn.bodyStart; index <= fn.bodyEnd && calls.length < MAX_CALLS_PER_FUNCTION; index += 1) {
    const line = lines[index] ?? "";
    regex.lastIndex = 0;
    for (let match = regex.exec(line); match && calls.length < MAX_CALLS_PER_FUNCTION; match = regex.exec(line)) {
      const callee = match[1];
      if (!callee || ignoredCalls.has(callee)) continue;
      if (index === fn.bodyStart && callee === fn.node.name) continue;
      calls.push({ callee, line: index + 1, direct: !callee.includes(".") });
    }
  }
  return calls;
}

async function readBoundedSource(root: string, file: IndexFileInput): Promise<{ content?: string; reason?: string }> {
  if (file.size > MAX_SOURCE_BYTES) return { reason: `source exceeds ${MAX_SOURCE_BYTES} bytes` };
  const absolute = resolve(root, file.path);
  let fileStat;
  try {
    fileStat = await stat(absolute);
  } catch {
    return { reason: "source file is unavailable" };
  }
  if (!fileStat.isFile()) return { reason: "path is not a regular file" };
  if (fileStat.size > MAX_SOURCE_BYTES) return { reason: `source exceeds ${MAX_SOURCE_BYTES} bytes` };
  return { content: await readFile(absolute, "utf8") };
}

export async function buildCallGraph(root: string, files: readonly IndexFileInput[]): Promise<CallGraph> {
  const selected = files.slice(0, MAX_FILES);
  const nodes: CallGraphNode[] = [];
  const edges: CallGraphEdge[] = [];
  const skippedFiles: Array<{ path: string; reason: string }> = [];

  for (const file of selected) {
    const extension = extname(file.path).toLowerCase();
    if (!jsExtensions.has(extension) && extension !== ".py") continue;

    const source = await readBoundedSource(root, file);
    if (!source.content) {
      skippedFiles.push({ path: normalizedPath(file.path), reason: source.reason ?? "source unavailable" });
      continue;
    }

    const parsed = extension === ".py"
      ? parsePythonFunctions(file.path, source.content)
      : parseJavascriptFunctions(file.path, source.content);
    const lines = source.content.split(/\r?\n/);
    const sameFileByName = new Map<string, CallGraphNode[]>();
    for (const fn of parsed) {
      nodes.push(fn.node);
      const bucket = sameFileByName.get(fn.node.name) ?? [];
      bucket.push(fn.node);
      sameFileByName.set(fn.node.name, bucket);
    }

    for (const fn of parsed) {
      for (const call of collectCalls(lines, fn)) {
        const candidates = call.direct ? sameFileByName.get(call.callee) ?? [] : [];
        const target = candidates.length === 1 ? candidates[0] : undefined;
        edges.push({
          from: fn.node.id,
          callee: call.callee,
          line: call.line,
          ...(target ? { target: target.id } : {}),
          resolution: target ? "same-file-function" : "external-or-unresolved",
        });
      }
    }
  }

  const resolvedEdgeCount = edges.filter((edge) => Boolean(edge.target)).length;
  return {
    schemaVersion: 1,
    nodes: nodes.sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line || a.name.localeCompare(b.name)),
    edges,
    resolvedEdgeCount,
    unresolvedEdgeCount: edges.length - resolvedEdgeCount,
    skippedFiles,
    interpretation: "lexical-call-evidence-only",
  };
}

function traverse(
  graph: CallGraph,
  root: string,
  direction: "callees" | "callers",
  maxDepth: number,
  maxNodes: number,
): Array<{ id: string; depth: number }> {
  const boundedDepth = Math.max(0, maxDepth);
  const boundedNodes = Math.max(1, maxNodes);
  const queue: Array<{ id: string; depth: number }> = [{ id: root, depth: 0 }];
  const seen = new Set<string>([root]);
  const output: Array<{ id: string; depth: number }> = [];

  while (queue.length > 0 && output.length < boundedNodes) {
    const current = queue.shift();
    if (!current || current.depth >= boundedDepth) continue;
    const adjacent = graph.edges.flatMap((edge) => {
      if (!edge.target) return [];
      if (direction === "callees" && edge.from === current.id) return [edge.target];
      if (direction === "callers" && edge.target === current.id) return [edge.from];
      return [];
    });

    for (const id of [...new Set(adjacent)].sort()) {
      if (seen.has(id)) continue;
      seen.add(id);
      const next = { id, depth: current.depth + 1 };
      output.push(next);
      queue.push(next);
      if (output.length >= boundedNodes) break;
    }
  }
  return output;
}

export function findCallNeighborhood(
  graph: CallGraph,
  root: string,
  maxDepth = 3,
  maxNodesPerDirection = 100,
): CallNeighborhood {
  return {
    root,
    maxDepth: Math.max(0, maxDepth),
    callees: traverse(graph, root, "callees", maxDepth, maxNodesPerDirection),
    callers: traverse(graph, root, "callers", maxDepth, maxNodesPerDirection),
    interpretation: "lexical-call-evidence-only",
  };
}
