import { posix } from "node:path";
import type { IndexFileInput, ModuleEdge, RepositoryIndex } from "./analysis.js";

export type ModuleResolution = "repository-file" | "external-or-unresolved";

export interface ResolvedModuleEdge extends ModuleEdge {
  target?: string;
  resolution: ModuleResolution;
}

export interface ModuleGraph {
  schemaVersion: 1;
  nodes: string[];
  edges: ResolvedModuleEdge[];
  resolvedEdgeCount: number;
  unresolvedEdgeCount: number;
}

export interface ModuleNeighborhood {
  root: string;
  maxDepth: number;
  dependencies: Array<{ path: string; depth: number }>;
  dependents: Array<{ path: string; depth: number }>;
  /** Module-level import reachability is structural evidence, not function-level data flow. */
  interpretation: "module-import-reachability-only";
}

const jsExtensions = [
  ".js", ".mjs", ".cjs", ".jsx",
  ".ts", ".mts", ".cts", ".tsx",
];

function normalizeRepositoryPath(value: string): string {
  const normalized = posix.normalize(value.replaceAll("\\", "/").replace(/^\.\//, ""));
  return normalized === "." ? "" : normalized.replace(/^\//, "");
}

function candidateLookup(files: readonly IndexFileInput[]): Map<string, string> {
  const lookup = new Map<string, string>();
  for (const file of files) {
    const normalized = normalizeRepositoryPath(file.path);
    if (!normalized || normalized.startsWith("../")) continue;
    lookup.set(normalized.toLowerCase(), normalized);
  }
  return lookup;
}

function addJsCandidates(candidates: string[], base: string): void {
  candidates.push(base);
  const extension = posix.extname(base).toLowerCase();
  if (!extension) {
    for (const ext of jsExtensions) candidates.push(`${base}${ext}`);
    for (const ext of jsExtensions) candidates.push(posix.join(base, `index${ext}`));
    return;
  }

  const sourceExtensionMap: Record<string, string[]> = {
    ".js": [".ts", ".tsx"],
    ".mjs": [".mts"],
    ".cjs": [".cts"],
    ".jsx": [".tsx"],
  };
  const stem = base.slice(0, -extension.length);
  for (const ext of sourceExtensionMap[extension] ?? []) candidates.push(`${stem}${ext}`);
}

function resolveJavascriptEdge(edge: ModuleEdge, lookup: Map<string, string>): string | undefined {
  if (!edge.specifier.startsWith(".")) return undefined;
  const base = normalizeRepositoryPath(posix.join(posix.dirname(normalizeRepositoryPath(edge.from)), edge.specifier));
  if (!base || base.startsWith("../")) return undefined;
  const candidates: string[] = [];
  addJsCandidates(candidates, base);
  for (const candidate of candidates) {
    const found = lookup.get(candidate.toLowerCase());
    if (found) return found;
  }
  return undefined;
}

function resolvePythonEdge(edge: ModuleEdge, lookup: Map<string, string>): string | undefined {
  if (!edge.specifier.startsWith(".")) return undefined;
  const leadingDots = edge.specifier.match(/^\.+/)?.[0].length ?? 0;
  let directory = posix.dirname(normalizeRepositoryPath(edge.from));
  for (let level = 1; level < leadingDots; level += 1) directory = posix.dirname(directory);
  const remainder = edge.specifier.slice(leadingDots).replaceAll(".", "/");
  const base = normalizeRepositoryPath(remainder ? posix.join(directory, remainder) : directory);
  if (!base || base.startsWith("../")) return undefined;
  for (const candidate of [`${base}.py`, posix.join(base, "__init__.py")]) {
    const found = lookup.get(candidate.toLowerCase());
    if (found) return found;
  }
  return undefined;
}

function resolveEdge(edge: ModuleEdge, lookup: Map<string, string>): string | undefined {
  if (edge.kind === "python-import") return resolvePythonEdge(edge, lookup);
  if (edge.kind === "import" || edge.kind === "require" || edge.kind === "dynamic-import") {
    return resolveJavascriptEdge(edge, lookup);
  }
  return undefined;
}

export function buildModuleGraph(index: RepositoryIndex, files: readonly IndexFileInput[]): ModuleGraph {
  const lookup = candidateLookup(files);
  const nodes = [...lookup.values()].sort();
  let resolvedEdgeCount = 0;
  const edges = index.moduleEdges.map((edge): ResolvedModuleEdge => {
    const target = resolveEdge(edge, lookup);
    if (target) {
      resolvedEdgeCount += 1;
      return { ...edge, target, resolution: "repository-file" };
    }
    return { ...edge, resolution: "external-or-unresolved" };
  });

  return {
    schemaVersion: 1,
    nodes,
    edges,
    resolvedEdgeCount,
    unresolvedEdgeCount: edges.length - resolvedEdgeCount,
  };
}

function traverse(
  graph: ModuleGraph,
  root: string,
  direction: "dependencies" | "dependents",
  maxDepth: number,
  maxNodes: number,
): Array<{ path: string; depth: number }> {
  const normalizedRoot = normalizeRepositoryPath(root);
  const boundedDepth = Math.max(0, maxDepth);
  const boundedNodes = Math.max(1, maxNodes);
  const queue: Array<{ path: string; depth: number }> = [{ path: normalizedRoot, depth: 0 }];
  const seen = new Set<string>([normalizedRoot.toLowerCase()]);
  const output: Array<{ path: string; depth: number }> = [];

  while (queue.length > 0 && output.length < boundedNodes) {
    const current = queue.shift();
    if (!current || current.depth >= boundedDepth) continue;

    const adjacent = graph.edges.flatMap((edge) => {
      if (!edge.target) return [];
      const from = normalizeRepositoryPath(edge.from);
      const target = normalizeRepositoryPath(edge.target);
      if (direction === "dependencies" && from.toLowerCase() === current.path.toLowerCase()) return [target];
      if (direction === "dependents" && target.toLowerCase() === current.path.toLowerCase()) return [from];
      return [];
    });

    for (const path of adjacent.sort()) {
      const key = path.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      const next = { path, depth: current.depth + 1 };
      output.push(next);
      queue.push(next);
      if (output.length >= boundedNodes) break;
    }
  }

  return output;
}

export function findModuleNeighborhood(
  graph: ModuleGraph,
  root: string,
  maxDepth = 3,
  maxNodesPerDirection = 100,
): ModuleNeighborhood {
  const normalizedRoot = normalizeRepositoryPath(root);
  return {
    root: normalizedRoot,
    maxDepth: Math.max(0, maxDepth),
    dependencies: traverse(graph, normalizedRoot, "dependencies", maxDepth, maxNodesPerDirection),
    dependents: traverse(graph, normalizedRoot, "dependents", maxDepth, maxNodesPerDirection),
    interpretation: "module-import-reachability-only",
  };
}
