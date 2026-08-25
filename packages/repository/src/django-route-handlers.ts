import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { IndexFileInput } from "./analysis.js";
import { findCallNeighborhood, type CallGraph, type CallGraphNode } from "./call-graph.js";
import type { ModuleGraph, ResolvedModuleEdge } from "./module-graph.js";
import type { RouteEntrypoint } from "./route-entrypoints.js";

const MAX_SOURCE_BYTES = 512_000;

interface PythonImportBinding {
  localName: string;
  importedName: string;
  edge: ResolvedModuleEdge;
}

function normalizePath(value: string): string {
  return value.replaceAll("\\", "/").replace(/^\.\//, "");
}

function insideRoot(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

async function safeReadSource(rootPath: string, file: IndexFileInput): Promise<string | undefined> {
  if (!file.path || file.path.includes("\0") || isAbsolute(file.path)) return undefined;
  const root = resolve(rootPath);
  const candidate = resolve(root, file.path);
  if (!insideRoot(root, candidate)) return undefined;
  const info = await lstat(candidate).catch(() => undefined);
  if (!info?.isFile() || info.isSymbolicLink() || info.size > MAX_SOURCE_BYTES) return undefined;
  return await readFile(candidate, "utf8").catch(() => undefined);
}

function explicitDjangoViewName(line: string): string | undefined {
  const match = line.match(
    /\bpath\s*\(\s*["'][^"']+["']\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))/,
  );
  return match?.[1];
}

function parsePythonNamedImport(line: string, edge: ResolvedModuleEdge): PythonImportBinding[] {
  const match = line.match(/^\s*from\s+([A-Za-z0-9_.]+)\s+import\s+(.+?)\s*(?:#.*)?$/);
  if (!match?.[1] || match[1] !== edge.specifier || !match[2] || match[2].includes("(")) return [];
  const output: PythonImportBinding[] = [];
  for (const raw of match[2].split(",")) {
    const part = raw.trim();
    if (!part || part === "*") continue;
    const binding = part.match(/^([A-Za-z_][A-Za-z0-9_]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?$/);
    const importedName = binding?.[1];
    if (!importedName) continue;
    output.push({ importedName, localName: binding?.[2] ?? importedName, edge });
  }
  return output;
}

function escapeIdentifier(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function bindingShadowedBeforeRoute(content: string, binding: PythonImportBinding, routeLine: number): boolean {
  if (routeLine <= binding.edge.line) return true;
  const escaped = escapeIdentifier(binding.localName);
  const lines = content.split(/\r?\n/).slice(binding.edge.line, routeLine - 1);
  const declaration = new RegExp(`^\\s*(?:async\\s+def|def|class)\\s+${escaped}\\b`);
  const assignment = new RegExp(`^\\s*${escaped}\\s*(?::[^=]+)?=(?!=)`);
  const loopBinding = new RegExp(`^\\s*(?:for|with)\\b[^:]*\\b${escaped}\\b`);
  const importBinding = new RegExp(`^\\s*(?:from\\s+[^\\s]+\\s+import|import)\\b.*\\b${escaped}\\b`);
  return lines.some((line) => declaration.test(line) || assignment.test(line) || loopBinding.test(line) || importBinding.test(line));
}

function uniqueNode(graph: CallGraph, path: string, name: string): CallGraphNode | undefined {
  const matches = graph.nodes.filter(
    (node) => normalizePath(node.path) === normalizePath(path) && node.name === name,
  );
  return matches.length === 1 ? matches[0] : undefined;
}

/**
 * Resolve explicit Django URLConf function views without executing repository code.
 *
 * Supported forms are deliberately narrow: `path("route/", view_name)` where `view_name` is either
 * one unique same-file Python function or one unshadowed `from module import name [as alias]` binding
 * whose module graph edge resolves to exactly one repository file containing exactly one function
 * with the imported name. Dotted members, class-based `as_view()`, lambdas, wrappers, wildcard or
 * parenthesized imports, dynamic expressions, ambiguous targets, and shadowed bindings remain
 * unresolved. Returned call neighborhoods are structural evidence only, not runtime reachability.
 */
export async function resolveDjangoRouteEntrypoints(
  rootPath: string,
  files: readonly IndexFileInput[],
  moduleGraph: ModuleGraph,
  graph: CallGraph,
  entrypoints: readonly RouteEntrypoint[],
  options: { maxCallDepth?: number; maxCallNodes?: number } = {},
): Promise<RouteEntrypoint[]> {
  const fileByPath = new Map(files.map((file) => [normalizePath(file.path), file]));
  const sourceCache = new Map<string, string | undefined>();
  const maxCallDepth = Math.max(0, Math.min(20, options.maxCallDepth ?? 3));
  const maxCallNodes = Math.max(1, Math.min(1_000, options.maxCallNodes ?? 100));
  const output: RouteEntrypoint[] = [];

  async function sourceFor(path: string): Promise<string | undefined> {
    const normalized = normalizePath(path);
    if (sourceCache.has(normalized)) return sourceCache.get(normalized);
    const file = fileByPath.get(normalized);
    const content = file ? await safeReadSource(rootPath, file) : undefined;
    sourceCache.set(normalized, content);
    return content;
  }

  for (const entrypoint of entrypoints) {
    const route = entrypoint.route;
    if (entrypoint.resolution !== "unresolved" || route.frameworkHint !== "Django URLConf") {
      output.push(entrypoint);
      continue;
    }

    const routePath = normalizePath(route.path);
    const content = await sourceFor(routePath);
    const routeLine = content?.split(/\r?\n/)[route.line - 1] ?? "";
    const localName = explicitDjangoViewName(routeLine);
    if (!content || !localName) {
      output.push(entrypoint);
      continue;
    }

    const candidates: CallGraphNode[] = [];
    const sameFile = uniqueNode(graph, routePath, localName);
    if (sameFile) candidates.push(sameFile);

    const lines = content.split(/\r?\n/);
    for (const edge of moduleGraph.edges) {
      if (
        normalizePath(edge.from) !== routePath ||
        edge.kind !== "python-import" ||
        edge.resolution !== "repository-file" ||
        !edge.target
      ) continue;
      const importLine = lines[edge.line - 1] ?? "";
      for (const binding of parsePythonNamedImport(importLine, edge)) {
        if (binding.localName !== localName || bindingShadowedBeforeRoute(content, binding, route.line)) continue;
        const target = uniqueNode(graph, edge.target, binding.importedName);
        if (target) candidates.push(target);
      }
    }

    const distinct = [...new Map(candidates.map((node) => [node.id, node])).values()];
    const handler = distinct.length === 1 ? distinct[0] : undefined;
    if (!handler) {
      output.push(entrypoint);
      continue;
    }

    output.push({
      route,
      resolution: handler.path === route.path ? "named-function" : "imported-named-function",
      handler,
      calls: findCallNeighborhood(graph, handler.id, maxCallDepth, maxCallNodes),
      interpretation: "structural-route-call-evidence-only",
    });
  }

  return output;
}
