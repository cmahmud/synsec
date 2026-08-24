import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { AuthSignal, IndexFileInput, RepositoryIndex, RouteSignal } from "./analysis.js";
import type { CallGraph, CallGraphNode } from "./call-graph.js";
import type { ImportCallLinkGraph } from "./import-call-links.js";
import type { ModuleGraph, ResolvedModuleEdge } from "./module-graph.js";
import type { RouteEntrypoint } from "./route-entrypoints.js";

const MAX_SOURCE_BYTES = 512_000;
const MAX_MIDDLEWARE_PER_ROUTE = 16;
const MAX_REACHABLE_NODES = 100;
const MAX_REACHABILITY_DEPTH = 3;

export type RouteMiddlewareResolution = "same-file-function" | "imported-named-function" | "unresolved";

export interface RouteMiddlewareAuthEvidence {
  path: string;
  line: number;
  kind: AuthSignal["kind"];
  middleware: string;
  functionName: string;
  depth: number;
}

export interface RouteMiddlewareBinding {
  name: string;
  position: number;
  resolution: RouteMiddlewareResolution;
  node?: {
    id: string;
    name: string;
    path: string;
    line: number;
    endLine: number;
  };
}

export interface RouteMiddlewareCompositionContext {
  route: RouteSignal;
  handler: string;
  middleware: RouteMiddlewareBinding[];
  authEvidence: RouteMiddlewareAuthEvidence[];
  status: "authorization-signal-observed" | "authentication-signal-observed" | "no-auth-signal-observed";
  callScope: "middleware-function-only" | "middleware-and-bounded-callees";
  /** Explicit named middleware composition is static structural evidence, not proof that middleware executes or protects the route. */
  interpretation: "structural-route-middleware-evidence-not-runtime-protection";
}

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
  const content = await readFile(candidate, "utf8").catch(() => undefined);
  return content === undefined || content.includes("\u0000") ? undefined : content;
}

function parseNamedRouteArguments(line: string, route: RouteSignal): string[] | undefined {
  if (route.frameworkHint !== "Node HTTP router" || route.method === "USE") return undefined;
  const registration = line.match(
    /\b(?:app|router|server)\.(?:get|post|put|patch|delete|options|head)\s*\(\s*(?:"[^"]*"|'[^']*'|`[^`]*`)\s*,\s*(.*?)\s*\)\s*;?\s*(?:\/\/.*)?$/i,
  );
  const args = registration?.[1]?.trim();
  if (!args || !/^[A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*)+$/.test(args)) return undefined;
  const names = args.split(",").map((value) => value.trim());
  return names.length >= 2 ? names : undefined;
}

function parseNamedImport(line: string, edge: ResolvedModuleEdge): ImportBinding[] {
  const match = line.match(/^\s*import\s*\{([^}]*)\}\s*from\s*["']([^"']+)["']/);
  if (!match?.[1] || match[2] !== edge.specifier) return [];
  const output: ImportBinding[] = [];
  for (const raw of match[1].split(",")) {
    const part = raw.trim().replace(/^type\s+/, "");
    const binding = part.match(/^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$/);
    const importedName = binding?.[1];
    if (importedName) output.push({ importedName, localName: binding?.[2] ?? importedName, edge });
  }
  return output;
}

function parseDestructuredRequire(line: string, edge: ResolvedModuleEdge): ImportBinding[] {
  const match = line.match(/^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*["']([^"']+)["']\s*\)/);
  if (!match?.[1] || match[2] !== edge.specifier) return [];
  const output: ImportBinding[] = [];
  for (const raw of match[1].split(",")) {
    const part = raw.trim();
    const binding = part.match(/^([A-Za-z_$][\w$]*)(?:\s*:\s*([A-Za-z_$][\w$]*))?$/);
    const importedName = binding?.[1];
    if (importedName) output.push({ importedName, localName: binding?.[2] ?? importedName, edge });
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

function hasNamedExportEvidence(content: string, binding: ImportBinding): boolean {
  const escaped = escapeIdentifier(binding.importedName);
  if (binding.edge.kind === "import") {
    return new RegExp(`(^|\\n)\\s*export\\s+(?:async\\s+)?function\\s+${escaped}\\b`).test(content)
      || new RegExp(`(^|\\n)\\s*export\\s+(?:const|let|var|class)\\s+${escaped}\\b`).test(content)
      || new RegExp(`(^|\\n)\\s*export\\s*\\{[^}]*\\b${escaped}\\b(?:\\s*,|\\s*\\})`).test(content);
  }
  if (binding.edge.kind === "require") {
    return new RegExp(`(^|\\n)\\s*(?:module\\.)?exports\\.${escaped}\\s*=\\s*${escaped}\\b`).test(content)
      || new RegExp(`(^|\\n)\\s*module\\.exports\\s*=\\s*\\{[^}]*\\b${escaped}\\b(?:\\s*[:,}]|\\s*,)`).test(content);
  }
  return false;
}

function localNode(graph: CallGraph, routePath: string, name: string): CallGraphNode | undefined {
  const matches = graph.nodes.filter((node) => normalizePath(node.path) === routePath && node.name === name);
  return matches.length === 1 ? matches[0] : undefined;
}

async function resolveImportedNode(
  routePath: string,
  routeLine: number,
  name: string,
  content: string,
  sourceFor: (path: string) => Promise<string | undefined>,
  moduleGraph: ModuleGraph,
  graph: CallGraph,
): Promise<CallGraphNode | undefined> {
  const lines = content.split(/\r?\n/);
  const bindings: ImportBinding[] = [];
  for (const edge of moduleGraph.edges) {
    if (normalizePath(edge.from) !== routePath || edge.resolution !== "repository-file" || !edge.target) continue;
    if (edge.kind !== "import" && edge.kind !== "require") continue;
    const sourceLine = lines[edge.line - 1] ?? "";
    const parsed = edge.kind === "import" ? parseNamedImport(sourceLine, edge) : parseDestructuredRequire(sourceLine, edge);
    for (const binding of parsed) {
      if (binding.localName === name && !bindingShadowedBeforeRoute(content, binding, routeLine)) bindings.push(binding);
    }
  }
  const candidates: CallGraphNode[] = [];
  for (const binding of bindings) {
    const target = binding.edge.target;
    if (!target) continue;
    const matches = graph.nodes.filter(
      (node) => normalizePath(node.path) === normalizePath(target) && node.name === binding.importedName,
    );
    if (matches.length !== 1) continue;
    const targetSource = await sourceFor(target);
    if (targetSource !== undefined && hasNamedExportEvidence(targetSource, binding)) candidates.push(matches[0]!);
  }
  const distinct = [...new Map(candidates.map((node) => [node.id, node])).values()];
  return distinct.length === 1 ? distinct[0] : undefined;
}

function reachableNodes(
  root: CallGraphNode,
  graph: CallGraph,
  importCallLinks: ImportCallLinkGraph,
  maxDepth: number,
  maxNodes: number,
): Map<string, number> {
  const depths = new Map<string, number>([[root.id, 0]]);
  const queue: Array<{ id: string; depth: number }> = [{ id: root.id, depth: 0 }];
  while (queue.length > 0 && depths.size < maxNodes) {
    const current = queue.shift();
    if (!current || current.depth >= maxDepth) continue;
    const sameFile = graph.edges.flatMap((edge) => edge.from === current.id && edge.target ? [edge.target] : []);
    const imported = importCallLinks.links.flatMap((link) => link.from === current.id ? [link.target] : []);
    for (const id of [...new Set([...sameFile, ...imported])].sort()) {
      if (depths.has(id)) continue;
      depths.set(id, current.depth + 1);
      queue.push({ id, depth: current.depth + 1 });
      if (depths.size >= maxNodes) break;
    }
  }
  return depths;
}

function statusFromEvidence(evidence: readonly RouteMiddlewareAuthEvidence[]): RouteMiddlewareCompositionContext["status"] {
  if (evidence.some((item) => item.kind === "authorization")) return "authorization-signal-observed";
  if (evidence.length > 0) return "authentication-signal-observed";
  return "no-auth-signal-observed";
}

function sameRoute(a: RouteSignal, b: RouteSignal): boolean {
  return normalizePath(a.path) === normalizePath(b.path) && a.line === b.line && a.method === b.method && a.route === b.route;
}

export async function buildRouteMiddlewareCompositionContexts(
  rootPath: string,
  files: readonly IndexFileInput[],
  index: RepositoryIndex,
  moduleGraph: ModuleGraph,
  graph: CallGraph,
  importCallLinks: ImportCallLinkGraph,
  entrypoints: readonly RouteEntrypoint[],
  options: { maxRoutes?: number; maxCallDepth?: number; maxCallNodes?: number } = {},
): Promise<RouteMiddlewareCompositionContext[]> {
  const fileByPath = new Map(files.map((file) => [normalizePath(file.path), file]));
  const sourceCache = new Map<string, string | undefined>();
  const maxRoutes = Math.max(0, Math.min(5_000, options.maxRoutes ?? 1_000));
  const maxDepth = Math.max(0, Math.min(MAX_REACHABILITY_DEPTH, options.maxCallDepth ?? 2));
  const maxNodes = Math.max(1, Math.min(MAX_REACHABLE_NODES, options.maxCallNodes ?? 50));

  async function sourceFor(path: string): Promise<string | undefined> {
    const normalized = normalizePath(path);
    if (sourceCache.has(normalized)) return sourceCache.get(normalized);
    const file = fileByPath.get(normalized);
    const content = file ? await safeReadSource(rootPath, file) : undefined;
    sourceCache.set(normalized, content);
    return content;
  }

  const output: RouteMiddlewareCompositionContext[] = [];
  for (const entrypoint of entrypoints.slice(0, maxRoutes)) {
    const route = entrypoint.route;
    if (route.frameworkHint !== "Node HTTP router") continue;
    const routePath = normalizePath(route.path);
    const content = await sourceFor(routePath);
    if (content === undefined) continue;
    const line = content.split(/\r?\n/)[route.line - 1] ?? "";
    const names = parseNamedRouteArguments(line, route);
    if (!names) continue;
    const handler = names.at(-1);
    if (!handler || (route.handler && route.handler !== handler)) continue;
    const middlewareNames = names.slice(0, -1,).slice(0, MAX_MIDDLEWARE_PER_ROUTE);
    if (middlewareNames.length === 0) continue;

    const middleware: RouteMiddlewareBinding[] = [];
    const evidence: RouteMiddlewareAuthEvidence[] = [];
    let usedCallees = false;
    for (let position = 0; position < middlewareNames.length; position += 1) {
      const name = middlewareNames[position]!;
      const local = localNode(graph, routePath, name);
      const imported = local ? undefined : await resolveImportedNode(routePath, route.line, name, content, sourceFor, moduleGraph, graph);
      const node = local ?? imported;
      middleware.push({
        name,
        position,
        resolution: local ? "same-file-function" : imported ? "imported-named-function" : "unresolved",
        ...(node ? { node: { id: node.id, name: node.name, path: node.path, line: node.line, endLine: node.endLine } } : {}),
      });
      if (!node) continue;
      const depths = reachableNodes(node, graph, importCallLinks, maxDepth, maxNodes);
      if ([...depths.values()].some((depth) => depth > 0)) usedCallees = true;
      for (const signal of index.authSignals) {
        const owners = graph.nodes.filter((candidate) => {
          if (!depths.has(candidate.id) || normalizePath(candidate.path) !== normalizePath(signal.path)) return false;
          return signal.line >= candidate.line && signal.line <= candidate.endLine;
        });
        if (owners.length !== 1) continue;
        const owner = owners[0]!;
        const depth = depths.get(owner.id);
        if (depth === undefined) continue;
        evidence.push({ path: signal.path, line: signal.line, kind: signal.kind, middleware: name, functionName: owner.name, depth });
      }
    }

    const uniqueEvidence = [...new Map(evidence.map((item) => [`${item.path}:${item.line}:${item.kind}:${item.middleware}:${item.functionName}`, item])).values()]
      .sort((a, b) => a.depth - b.depth || a.path.localeCompare(b.path) || a.line - b.line);
    output.push({
      route,
      handler,
      middleware,
      authEvidence: uniqueEvidence,
      status: statusFromEvidence(uniqueEvidence),
      callScope: usedCallees ? "middleware-and-bounded-callees" : "middleware-function-only",
      interpretation: "structural-route-middleware-evidence-not-runtime-protection",
    });
  }

  return output.filter((context) => entrypoints.some((entrypoint) => sameRoute(entrypoint.route, context.route)));
}
