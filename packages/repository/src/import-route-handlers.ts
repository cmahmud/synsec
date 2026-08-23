import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { IndexFileInput } from "./analysis.js";
import { findCallNeighborhood, type CallGraph, type CallGraphNode } from "./call-graph.js";
import type { ModuleGraph, ResolvedModuleEdge } from "./module-graph.js";
import type { RouteEntrypoint } from "./route-entrypoints.js";

const MAX_SOURCE_BYTES = 512_000;

interface ImportBinding {
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

function parseNamedImport(line: string, edge: ResolvedModuleEdge): ImportBinding[] {
  const match = line.match(/^\s*import\s*\{([^}]*)\}\s*from\s*["']([^"']+)["']/);
  if (!match?.[1] || match[2] !== edge.specifier) return [];
  const output: ImportBinding[] = [];
  for (const raw of match[1].split(",")) {
    const part = raw.trim().replace(/^type\s+/, "");
    if (!part) continue;
    const binding = part.match(/^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$/);
    const importedName = binding?.[1];
    if (!importedName) continue;
    output.push({ importedName, localName: binding?.[2] ?? importedName, edge });
  }
  return output;
}

function parseDestructuredRequire(line: string, edge: ResolvedModuleEdge): ImportBinding[] {
  const match = line.match(
    /^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*["']([^"']+)["']\s*\)/,
  );
  if (!match?.[1] || match[2] !== edge.specifier) return [];
  const output: ImportBinding[] = [];
  for (const raw of match[1].split(",")) {
    const part = raw.trim();
    if (!part) continue;
    const binding = part.match(/^([A-Za-z_$][\w$]*)(?:\s*:\s*([A-Za-z_$][\w$]*))?$/);
    const importedName = binding?.[1];
    if (!importedName) continue;
    output.push({ importedName, localName: binding?.[2] ?? importedName, edge });
  }
  return output;
}

function escapeIdentifier(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function bindingShadowedBeforeRoute(content: string, binding: ImportBinding, routeLine: number): boolean {
  if (routeLine <= binding.edge.line) return true;
  const escaped = escapeIdentifier(binding.localName);
  const lines = content.split(/\r?\n/).slice(binding.edge.line, routeLine - 1);
  const declaration = new RegExp(`\\b(?:const|let|var|function|class)\\s+${escaped}\\b`);
  const assignment = new RegExp(`(^|[^.\\w$])${escaped}\\s*=(?!=)`);
  const parameter = new RegExp(`\\([^)]*\\b${escaped}\\b[^)]*\\)\\s*(?:=>|\\{)`);
  return lines.some((line) => declaration.test(line) || assignment.test(line) || parameter.test(line));
}

function targetNode(graph: CallGraph, binding: ImportBinding): CallGraphNode | undefined {
  const targetPath = binding.edge.target;
  if (!targetPath) return undefined;
  const matches = graph.nodes.filter(
    (node) => normalizePath(node.path) === normalizePath(targetPath) && node.name === binding.importedName,
  );
  return matches.length === 1 ? matches[0] : undefined;
}

function hasNamedExportEvidence(content: string, binding: ImportBinding): boolean {
  const escaped = escapeIdentifier(binding.importedName);
  if (binding.edge.kind === "import") {
    const directFunction = new RegExp(`(^|\\n)\\s*export\\s+(?:async\\s+)?function\\s+${escaped}\\b`);
    const directValue = new RegExp(`(^|\\n)\\s*export\\s+(?:const|let|var|class)\\s+${escaped}\\b`);
    const exportList = new RegExp(`(^|\\n)\\s*export\\s*\\{[^}]*\\b${escaped}\\b(?:\\s*,|\\s*\\})`);
    return directFunction.test(content) || directValue.test(content) || exportList.test(content);
  }

  if (binding.edge.kind === "require") {
    const propertyAssignment = new RegExp(
      `(^|\\n)\\s*(?:module\\.)?exports\\.${escaped}\\s*=\\s*${escaped}\\b`,
    );
    const objectAssignment = new RegExp(
      `(^|\\n)\\s*module\\.exports\\s*=\\s*\\{[^}]*\\b${escaped}\\b(?:\\s*[:,}]|\\s*,)`,
    );
    return propertyAssignment.test(content) || objectAssignment.test(content);
  }

  return false;
}

/**
 * Resolve unresolved Node router handlers through explicit repository-local named imports.
 *
 * Only ES named imports and destructured CommonJS require bindings are supported. Default imports,
 * namespace members, re-exports, dynamic expressions, shadowed bindings, missing export evidence,
 * ambiguous module targets, and ambiguous target functions remain unresolved. This is structural
 * evidence only.
 */
export async function resolveImportedNodeRouteEntrypoints(
  rootPath: string,
  files: readonly IndexFileInput[],
  moduleGraph: ModuleGraph,
  graph: CallGraph,
  entrypoints: readonly RouteEntrypoint[],
  options: { maxCallDepth?: number; maxCallNodes?: number } = {},
): Promise<RouteEntrypoint[]> {
  const fileByPath = new Map(files.map((file) => [normalizePath(file.path), file]));
  const sourceCache = new Map<string, string | undefined>();
  const maxCallDepth = options.maxCallDepth ?? 3;
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
    if (
      entrypoint.resolution !== "unresolved" ||
      route.frameworkHint !== "Node HTTP router" ||
      !route.handler
    ) {
      output.push(entrypoint);
      continue;
    }

    const routePath = normalizePath(route.path);
    const content = await sourceFor(routePath);
    if (content === undefined) {
      output.push(entrypoint);
      continue;
    }

    const lines = content.split(/\r?\n/);
    const bindings: ImportBinding[] = [];
    for (const edge of moduleGraph.edges) {
      if (
        normalizePath(edge.from) !== routePath ||
        edge.resolution !== "repository-file" ||
        !edge.target ||
        (edge.kind !== "import" && edge.kind !== "require")
      ) continue;
      const line = lines[edge.line - 1] ?? "";
      const parsed = edge.kind === "import" ? parseNamedImport(line, edge) : parseDestructuredRequire(line, edge);
      for (const binding of parsed) {
        if (binding.localName === route.handler && !bindingShadowedBeforeRoute(content, binding, route.line)) {
          bindings.push(binding);
        }
      }
    }

    const eligibleTargets: CallGraphNode[] = [];
    for (const binding of bindings) {
      const node = targetNode(graph, binding);
      const targetPath = binding.edge.target;
      if (!node || !targetPath) continue;
      const targetSource = await sourceFor(targetPath);
      if (targetSource !== undefined && hasNamedExportEvidence(targetSource, binding)) {
        eligibleTargets.push(node);
      }
    }

    const distinct = [...new Map(eligibleTargets.map((node) => [node.id, node])).values()];
    const handler = distinct.length === 1 ? distinct[0] : undefined;
    if (!handler) {
      output.push(entrypoint);
      continue;
    }

    output.push({
      route,
      resolution: "imported-named-function",
      handler,
      calls: findCallNeighborhood(graph, handler.id, maxCallDepth, maxCallNodes),
      interpretation: "structural-route-call-evidence-only",
    });
  }

  return output;
}
