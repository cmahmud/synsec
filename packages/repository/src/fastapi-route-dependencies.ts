import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { AuthSignal, IndexFileInput, RepositoryIndex, RouteSignal } from "./analysis.js";
import { findCallNeighborhood, type CallGraph, type CallGraphNode, type CallNeighborhood } from "./call-graph.js";
import type { ModuleGraph, ResolvedModuleEdge } from "./module-graph.js";
import type { RouteEntrypoint } from "./route-entrypoints.js";

const MAX_SOURCE_BYTES = 512_000;
const DEFAULT_MAX_ROUTES = 1_000;
const MAX_ROUTES = 5_000;
const DEFAULT_MAX_EVIDENCE = 100;
const MAX_EVIDENCE = 1_000;
const MAX_HANDLER_SIGNATURE_LENGTH = 16_384;
const MAX_HANDLER_DECLARATION_DISTANCE = 5;

interface PythonImportBinding {
  localName: string;
  importedName: string;
  edge: ResolvedModuleEdge;
}

interface DependencyDeclaration {
  name: string;
  wrapper: "Depends" | "Security";
  source: "route-list" | "handler-parameter";
  useLine: number;
  parameter?: string;
}

export interface FastApiRouteDependency {
  name: string;
  wrapper: "Depends" | "Security";
  source: "route-list" | "handler-parameter";
  parameter?: string;
  resolution: "same-file-function" | "imported-named-function" | "unresolved";
  node?: CallGraphNode;
  calls?: CallNeighborhood;
}

export interface FastApiRouteDependencyAuthEvidence {
  path: string;
  line: number;
  kind: AuthSignal["kind"];
  dependency: string;
  depth: number;
}

export interface FastApiRouteDependencyContext {
  route: RouteSignal;
  handler?: string;
  dependencies: FastApiRouteDependency[];
  authEvidence: FastApiRouteDependencyAuthEvidence[];
  status: "auth-signal-observed" | "no-auth-signal-observed";
  callScope: "dependency-and-bounded-callees";
  /** Dependency wiring and lexical auth signals are structural evidence, not proof of runtime protection. */
  interpretation: "structural-fastapi-dependency-evidence-not-runtime-protection";
}

function normalizePath(value: string): string {
  return value.replaceAll("\\", "/").replace(/^\.\//, "");
}

function insideRoot(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

function boundedInteger(value: number | undefined, fallback: number, maximum: number, label: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < 1 || resolved > maximum) {
    throw new Error(`${label} must be an integer between 1 and ${maximum}.`);
  }
  return resolved;
}

async function safeReadSource(rootPath: string, file: IndexFileInput): Promise<string | undefined> {
  if (!file.path || file.path.includes("\0") || isAbsolute(file.path)) return undefined;
  const root = resolve(rootPath);
  const candidate = resolve(root, file.path);
  if (!insideRoot(root, candidate)) return undefined;
  const info = await lstat(candidate).catch(() => undefined);
  if (!info?.isFile() || info.isSymbolicLink() || info.size > MAX_SOURCE_BYTES) return undefined;
  const content = await readFile(candidate, "utf8").catch(() => undefined);
  return content?.includes("\u0000") ? undefined : content;
}

function escapeIdentifier(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function explicitFastApiDecorator(line: string): boolean {
  return /^\s*@(app|router)\.(get|post|put|patch|delete|options|head|route)\s*\(/i.test(line);
}

function explicitFastApiWrappers(content: string, useLine: number): Set<"Depends" | "Security"> {
  const wrappers = new Set<"Depends" | "Security">();
  const prefix = content.split(/\r?\n/).slice(0, Math.max(0, useLine - 1));
  for (const line of prefix) {
    const match = line.match(/^\s*from\s+fastapi(?:\.[A-Za-z0-9_.]+)?\s+import\s+(.+?)\s*(?:#.*)?$/);
    if (!match?.[1] || match[1].includes("(")) continue;
    for (const raw of match[1].split(",")) {
      const part = raw.trim();
      if (part === "Depends") wrappers.add("Depends");
      if (part === "Security") wrappers.add("Security");
    }
  }

  for (const wrapper of [...wrappers]) {
    const escaped = escapeIdentifier(wrapper);
    const declaration = new RegExp(`^\\s*(?:async\\s+def|def|class)\\s+${escaped}\\b`);
    const assignment = new RegExp(`^\\s*${escaped}\\s*(?::[^=]+)?=(?!=)`);
    if (prefix.some((line) => declaration.test(line) || assignment.test(line))) wrappers.delete(wrapper);
  }
  return wrappers;
}

function parseExplicitRouteDependencies(
  line: string,
  useLine: number,
  allowedWrappers: ReadonlySet<"Depends" | "Security">,
): DependencyDeclaration[] | undefined {
  const hasDependencies = /\bdependencies\s*=/.test(line);
  const match = line.match(/\bdependencies\s*=\s*\[([^\]]*)\]/);
  if (!match) return hasDependencies ? undefined : [];
  const body = match[1]?.trim() ?? "";
  if (!body) return [];
  const parts = body.split(",").map((value) => value.trim()).filter(Boolean);
  const output: DependencyDeclaration[] = [];
  for (const part of parts) {
    const dependency = part.match(/^(Depends|Security)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)$/);
    const wrapper = dependency?.[1] as "Depends" | "Security" | undefined;
    const name = dependency?.[2];
    if (!wrapper || !name || !allowedWrappers.has(wrapper)) return undefined;
    output.push({ wrapper, name, source: "route-list", useLine });
  }
  return output;
}

function parseExplicitHandlerDependencies(
  line: string,
  useLine: number,
  handlerName: string,
  allowedWrappers: ReadonlySet<"Depends" | "Security">,
): DependencyDeclaration[] | undefined {
  if (!line || line.length > MAX_HANDLER_SIGNATURE_LENGTH) return undefined;
  const escapedHandler = escapeIdentifier(handlerName);
  const signature = line.match(new RegExp(`^\\s*(?:async\\s+)?def\\s+${escapedHandler}\\s*\\((.*)\\)\\s*(?:->\\s*[^:]+)?\\s*:\\s*(?:#.*)?$`));
  if (!signature) return undefined;
  const parameters = signature[1] ?? "";
  if (!/\b(?:Depends|Security)\s*\(/.test(parameters)) return [];

  const output: DependencyDeclaration[] = [];
  const matcher = /(?:^|,)\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[^=,]+)?=\s*(Depends|Security)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*(?=,|$)/g;
  let match: RegExpExecArray | null;
  while ((match = matcher.exec(parameters)) !== null) {
    const parameter = match[1];
    const wrapper = match[2] as "Depends" | "Security" | undefined;
    const name = match[3];
    if (!parameter || !wrapper || !name || !allowedWrappers.has(wrapper)) return undefined;
    output.push({ parameter, wrapper, name, source: "handler-parameter", useLine });
  }

  const wrapperCount = [...parameters.matchAll(/\b(?:Depends|Security)\s*\(/g)].length;
  return output.length === wrapperCount ? output : undefined;
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

function bindingShadowedBeforeUse(content: string, binding: PythonImportBinding, useLine: number): boolean {
  if (useLine <= binding.edge.line) return true;
  const escaped = escapeIdentifier(binding.localName);
  const lines = content.split(/\r?\n/).slice(binding.edge.line, useLine - 1);
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

function sameRoute(left: RouteSignal, right: RouteSignal): boolean {
  return normalizePath(left.path) === normalizePath(right.path)
    && left.line === right.line
    && left.method === right.method
    && left.route === right.route;
}

function nearestFastApiHandler(graph: CallGraph, path: string, routeLine: number): CallGraphNode | undefined {
  const candidates = graph.nodes
    .filter((node) => (
      node.kind === "python-function"
      && normalizePath(node.path) === normalizePath(path)
      && node.line > routeLine
      && node.line - routeLine <= MAX_HANDLER_DECLARATION_DISTANCE
    ))
    .sort((left, right) => left.line - right.line || left.name.localeCompare(right.name));
  const first = candidates[0];
  if (!first) return undefined;
  const nearest = candidates.filter((candidate) => candidate.line === first.line);
  return nearest.length === 1 ? first : undefined;
}

function evidenceForDependency(
  dependency: FastApiRouteDependency,
  index: RepositoryIndex,
  graph: CallGraph,
  remaining: number,
): FastApiRouteDependencyAuthEvidence[] {
  if (!dependency.node || remaining <= 0) return [];
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
  const scoped: Array<{ node: CallGraphNode; depth: number }> = [{ node: dependency.node, depth: 0 }];
  for (const callee of dependency.calls?.callees ?? []) {
    const node = nodeById.get(callee.id);
    if (node) scoped.push({ node, depth: callee.depth });
  }

  const output: FastApiRouteDependencyAuthEvidence[] = [];
  for (const scope of scoped) {
    for (const signal of index.authSignals) {
      if (
        normalizePath(signal.path) !== normalizePath(scope.node.path) ||
        signal.line < scope.node.line ||
        signal.line > scope.node.endLine
      ) continue;
      output.push({
        path: signal.path,
        line: signal.line,
        kind: signal.kind,
        dependency: dependency.name,
        depth: scope.depth,
      });
      if (output.length >= remaining) return output;
    }
  }
  return output;
}

/**
 * Resolve explicit FastAPI route dependencies without importing or executing repository code.
 *
 * Supported forms are literal route-level `dependencies=[Depends(name), Security(name)]` entries and
 * one-line handler parameters such as `user = Depends(require_user)`. Wrappers must be explicitly
 * imported from FastAPI without aliasing and remain unshadowed at the use site. Dependency names
 * resolve to one unique already-defined same-file Python function or one unshadowed explicit
 * repository-local `from module import name [as alias]` binding. Factories, dotted members, dynamic
 * lists, multiline signatures, nested expressions, wildcard/parenthesized imports, ambiguous targets,
 * and shadowed names fail closed. Auth evidence is lexical evidence within the resolved dependency and
 * bounded same-file callees; it is not proof the dependency executes, authorizes a request, or makes a
 * route secure. The analyzer independently revalidates `@app` / `@router` decorator syntax and the
 * nearest following Python function from bounded source/call-graph evidence instead of trusting a
 * generic route framework hint to establish FastAPI identity or handler ownership.
 */
export async function buildFastApiRouteDependencyContexts(
  rootPath: string,
  files: readonly IndexFileInput[],
  index: RepositoryIndex,
  moduleGraph: ModuleGraph,
  graph: CallGraph,
  entrypoints: readonly RouteEntrypoint[],
  options: { maxRoutes?: number; maxCallDepth?: number; maxCallNodes?: number; maxEvidence?: number } = {},
): Promise<FastApiRouteDependencyContext[]> {
  const maxRoutes = boundedInteger(options.maxRoutes, DEFAULT_MAX_ROUTES, MAX_ROUTES, "FastAPI dependency maxRoutes");
  const maxCallDepth = Math.max(0, Math.min(20, options.maxCallDepth ?? 3));
  const maxCallNodes = Math.max(1, Math.min(1_000, options.maxCallNodes ?? 100));
  const maxEvidence = boundedInteger(options.maxEvidence, DEFAULT_MAX_EVIDENCE, MAX_EVIDENCE, "FastAPI dependency maxEvidence");
  const fileByPath = new Map(files.map((file) => [normalizePath(file.path), file]));
  const sourceCache = new Map<string, string | undefined>();
  const output: FastApiRouteDependencyContext[] = [];

  async function sourceFor(path: string): Promise<string | undefined> {
    const normalized = normalizePath(path);
    if (sourceCache.has(normalized)) return sourceCache.get(normalized);
    const file = fileByPath.get(normalized);
    const source = file ? await safeReadSource(rootPath, file) : undefined;
    sourceCache.set(normalized, source);
    return source;
  }

  for (const indexedRoute of index.routes) {
    if (output.length >= maxRoutes) break;
    const routePath = normalizePath(indexedRoute.path);
    const content = await sourceFor(routePath);
    if (!content) continue;
    const lines = content.split(/\r?\n/);
    const routeLine = lines[indexedRoute.line - 1] ?? "";
    if (!explicitFastApiDecorator(routeLine)) continue;

    const routeDeclarations = parseExplicitRouteDependencies(
      routeLine,
      indexedRoute.line,
      explicitFastApiWrappers(content, indexedRoute.line),
    );
    if (!routeDeclarations) continue;

    const entrypoint = entrypoints.find((candidate) => sameRoute(candidate.route, indexedRoute));
    const entrypointHandler = entrypoint?.handler;
    const handler = entrypointHandler?.kind === "python-function"
      && normalizePath(entrypointHandler.path) === routePath
      ? entrypointHandler
      : nearestFastApiHandler(graph, routePath, indexedRoute.line);
    let handlerDeclarations: DependencyDeclaration[] = [];
    if (handler) {
      const handlerLine = lines[handler.line - 1] ?? "";
      const parsed = parseExplicitHandlerDependencies(
        handlerLine,
        handler.line,
        handler.name,
        explicitFastApiWrappers(content, handler.line),
      );
      if (parsed === undefined && /\b(?:Depends|Security)\s*\(/.test(handlerLine)) continue;
      handlerDeclarations = parsed ?? [];
    }

    const declarations = [...routeDeclarations, ...handlerDeclarations];
    if (declarations.length === 0) continue;
    const route: RouteSignal = { ...indexedRoute, frameworkHint: "FastAPI route decorator" };
    const dependencies: FastApiRouteDependency[] = [];

    for (const declaration of declarations) {
      const candidates: Array<{ node: CallGraphNode; resolution: "same-file-function" | "imported-named-function" }> = [];
      const sameFile = uniqueNode(graph, routePath, declaration.name);
      if (sameFile && sameFile.line < declaration.useLine) {
        candidates.push({ node: sameFile, resolution: "same-file-function" });
      }

      for (const edge of moduleGraph.edges) {
        if (
          normalizePath(edge.from) !== routePath ||
          edge.kind !== "python-import" ||
          edge.resolution !== "repository-file" ||
          !edge.target
        ) continue;
        const importLine = lines[edge.line - 1] ?? "";
        for (const binding of parsePythonNamedImport(importLine, edge)) {
          if (
            binding.localName !== declaration.name ||
            bindingShadowedBeforeUse(content, binding, declaration.useLine)
          ) continue;
          const target = uniqueNode(graph, edge.target, binding.importedName);
          if (target) candidates.push({ node: target, resolution: "imported-named-function" });
        }
      }

      const distinct = [...new Map(candidates.map((candidate) => [candidate.node.id, candidate])).values()];
      const resolved = distinct.length === 1 ? distinct[0] : undefined;
      dependencies.push({
        name: declaration.name,
        wrapper: declaration.wrapper,
        source: declaration.source,
        ...(declaration.parameter ? { parameter: declaration.parameter } : {}),
        resolution: resolved?.resolution ?? "unresolved",
        ...(resolved ? {
          node: resolved.node,
          calls: findCallNeighborhood(graph, resolved.node.id, maxCallDepth, maxCallNodes),
        } : {}),
      });
    }

    const authEvidence: FastApiRouteDependencyAuthEvidence[] = [];
    for (const dependency of dependencies) {
      authEvidence.push(...evidenceForDependency(dependency, index, graph, maxEvidence - authEvidence.length));
      if (authEvidence.length >= maxEvidence) break;
    }

    output.push({
      route,
      ...(handler ? { handler: handler.name } : {}),
      dependencies,
      authEvidence,
      status: authEvidence.length > 0 ? "auth-signal-observed" : "no-auth-signal-observed",
      callScope: "dependency-and-bounded-callees",
      interpretation: "structural-fastapi-dependency-evidence-not-runtime-protection",
    });
  }
  return output;
}
