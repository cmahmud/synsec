import { lstat, readFile } from "node:fs/promises";
import { extname, isAbsolute, relative, resolve, sep } from "node:path";
import type { IndexFileInput } from "./analysis.js";
import type { ModuleGraph, ResolvedModuleEdge } from "./module-graph.js";
import type { RouteEntrypoint } from "./route-entrypoints.js";

const MAX_SOURCE_BYTES = 512_000;
const DEFAULT_MAX_INCLUDE_DEPTH = 8;
const MAX_INCLUDE_DEPTH = 32;
const DEFAULT_MAX_COMPOSED_ROUTES = 2_000;
const MAX_COMPOSED_ROUTES = 10_000;

interface RouterNode {
  path: string;
  name: string;
  prefix: string;
  declarationLine: number;
}

interface ImportedRouterBinding {
  localName: string;
  importedName: string;
  edge: ResolvedModuleEdge;
}

interface RouterIncludeEdge {
  parent?: RouterNode;
  child: RouterNode;
  prefix: string;
}

export interface FastApiComposedRouteEntrypoint extends RouteEntrypoint {
  composition: {
    rootPath: string;
    includeDepth: number;
    routerPath: string;
    routerName: string;
    prefixes: string[];
  };
  /** Static router-prefix composition is not proof that FastAPI registers or serves the route. */
  compositionInterpretation: "structural-fastapi-router-composition-not-runtime-reachability";
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

function normalizePrefix(value: string): string {
  if (!value || value === "/") return "";
  const segments = value.split("/").filter(Boolean);
  return segments.length === 0 ? "" : `/${segments.join("/")}`;
}

function composeRoute(parts: readonly string[]): string {
  const segments = parts.flatMap((part) => part.split("/").filter(Boolean));
  return segments.length === 0 ? "/" : `/${segments.join("/")}`;
}

function escapeIdentifier(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function safeReadSource(rootPath: string, file: IndexFileInput): Promise<string | undefined> {
  if (!file.path || file.path.includes("\0") || isAbsolute(file.path) || extname(file.path).toLowerCase() !== ".py") {
    return undefined;
  }
  const root = resolve(rootPath);
  const candidate = resolve(root, file.path);
  if (!insideRoot(root, candidate)) return undefined;
  const info = await lstat(candidate).catch(() => undefined);
  if (!info?.isFile() || info.isSymbolicLink() || info.size > MAX_SOURCE_BYTES) return undefined;
  const content = await readFile(candidate, "utf8").catch(() => undefined);
  return content?.includes("\u0000") ? undefined : content;
}

function explicitFastApiRouterImport(content: string, beforeLine: number): boolean {
  const lines = content.split(/\r?\n/).slice(0, Math.max(0, beforeLine - 1));
  let imported = false;
  for (const line of lines) {
    const match = line.match(/^\s*from\s+fastapi\s+import\s+(.+?)\s*(?:#.*)?$/);
    if (!match?.[1] || match[1].includes("(")) continue;
    for (const raw of match[1].split(",")) {
      if (raw.trim() === "APIRouter") imported = true;
    }
  }
  if (!imported) return false;
  return !lines.some((line) => /^\s*(?:async\s+def|def|class)\s+APIRouter\b/.test(line) || /^\s*APIRouter\s*(?::[^=]+)?=(?!=)/.test(line));
}

function parseRouterDeclaration(line: string): { name: string; prefix: string } | undefined {
  const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*APIRouter\s*\((.*)\)\s*(?:#.*)?$/);
  const name = match?.[1];
  const args = match?.[2]?.trim();
  if (!name || args === undefined) return undefined;
  if (!args) return { name, prefix: "" };
  const prefix = args.match(/^prefix\s*=\s*(["'])([^"']*)\1(?:\s*,\s*)?$/);
  if (!prefix?.[2] && prefix?.[2] !== "") return undefined;
  return { name, prefix: normalizePrefix(prefix[2]) };
}

function parseNamedImport(line: string, edge: ResolvedModuleEdge): ImportedRouterBinding[] {
  const match = line.match(/^\s*from\s+([A-Za-z0-9_.]+)\s+import\s+(.+?)\s*(?:#.*)?$/);
  if (!match?.[1] || match[1] !== edge.specifier || !match[2] || match[2].includes("(")) return [];
  const output: ImportedRouterBinding[] = [];
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

function bindingShadowedBeforeUse(content: string, binding: ImportedRouterBinding, useLine: number): boolean {
  if (useLine <= binding.edge.line) return true;
  const escaped = escapeIdentifier(binding.localName);
  const lines = content.split(/\r?\n/).slice(binding.edge.line, useLine - 1);
  const declaration = new RegExp(`^\\s*(?:async\\s+def|def|class)\\s+${escaped}\\b`);
  const assignment = new RegExp(`^\\s*${escaped}\\s*(?::[^=]+)?=(?!=)`);
  const importBinding = new RegExp(`^\\s*(?:from\\s+[^\\s]+\\s+import|import)\\b.*\\b${escaped}\\b`);
  return lines.some((line) => declaration.test(line) || assignment.test(line) || importBinding.test(line));
}

function parseInclude(line: string): { parentName?: string; childName: string; prefix: string } | undefined {
  const match = line.match(/^\s*(app|[A-Za-z_][A-Za-z0-9_]*)\.include_router\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)(?:\s*,\s*prefix\s*=\s*(["'])([^"']*)\3)?\s*\)\s*(?:#.*)?$/);
  const receiver = match?.[1];
  const childName = match?.[2];
  if (!receiver || !childName) return undefined;
  return {
    ...(receiver === "app" ? {} : { parentName: receiver }),
    childName,
    prefix: normalizePrefix(match?.[4] ?? ""),
  };
}

function routerKey(path: string, name: string): string {
  return `${normalizePath(path)}\0${name}`;
}

function routeKey(entrypoint: RouteEntrypoint): string {
  const handler = entrypoint.handler;
  return [normalizePath(entrypoint.route.path), entrypoint.route.line, entrypoint.route.method, entrypoint.route.route, handler?.id ?? ""].join("\0");
}

/**
 * Compose explicit FastAPI APIRouter prefixes across bounded include_router() relationships.
 *
 * Only one-line `name = APIRouter()` / `name = APIRouter(prefix="literal")` declarations with an
 * explicit unaliased `from fastapi import APIRouter` are router nodes. Include edges must be exact
 * `app.include_router(name[, prefix="literal"])` or `parent.include_router(name[, prefix="literal"])`
 * calls. Imported child routers require an unshadowed repository-local named `from ... import ...`
 * binding whose target contains exactly one matching APIRouter declaration. Dotted references,
 * factories, dynamic prefixes, multiline expressions, wildcard imports, ambiguous declarations,
 * and unresolved imports fail closed. Traversal starts only at explicit `app.include_router` roots,
 * stops at repeated router nodes, and is bounded by depth/output limits. The returned route identity
 * is structural evidence; it is not proof that FastAPI imports, registers, or serves the route.
 */
export async function composeFastApiRouterEntrypoints(
  rootPath: string,
  files: readonly IndexFileInput[],
  moduleGraph: ModuleGraph,
  entrypoints: readonly RouteEntrypoint[],
  options: { maxIncludeDepth?: number; maxComposedRoutes?: number } = {},
): Promise<RouteEntrypoint[]> {
  const maxIncludeDepth = boundedInteger(options.maxIncludeDepth, DEFAULT_MAX_INCLUDE_DEPTH, MAX_INCLUDE_DEPTH, "FastAPI router maxIncludeDepth");
  const maxComposedRoutes = boundedInteger(options.maxComposedRoutes, DEFAULT_MAX_COMPOSED_ROUTES, MAX_COMPOSED_ROUTES, "FastAPI router maxComposedRoutes");
  const pythonFiles = files.filter((file) => extname(file.path).toLowerCase() === ".py");
  const sourceByPath = new Map<string, string>();
  for (const file of pythonFiles) {
    const source = await safeReadSource(rootPath, file);
    if (source !== undefined) sourceByPath.set(normalizePath(file.path), source);
  }

  const routers = new Map<string, RouterNode>();
  const ambiguousRouters = new Set<string>();
  for (const [path, content] of sourceByPath) {
    const lines = content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const parsed = parseRouterDeclaration(lines[index] ?? "");
      if (!parsed || !explicitFastApiRouterImport(content, index + 1)) continue;
      const key = routerKey(path, parsed.name);
      if (routers.has(key)) {
        routers.delete(key);
        ambiguousRouters.add(key);
        continue;
      }
      if (!ambiguousRouters.has(key)) {
        routers.set(key, { path, name: parsed.name, prefix: parsed.prefix, declarationLine: index + 1 });
      }
    }
  }

  const importBindingsByPath = new Map<string, ImportedRouterBinding[]>();
  for (const edge of moduleGraph.edges) {
    if (edge.kind !== "python-import" || edge.resolution !== "repository-file" || !edge.target) continue;
    const path = normalizePath(edge.from);
    const content = sourceByPath.get(path);
    if (!content) continue;
    const line = content.split(/\r?\n/)[edge.line - 1] ?? "";
    const bindings = parseNamedImport(line, edge);
    if (bindings.length === 0) continue;
    importBindingsByPath.set(path, [...(importBindingsByPath.get(path) ?? []), ...bindings]);
  }

  function resolveRouter(path: string, localName: string, useLine: number): RouterNode | undefined {
    const normalized = normalizePath(path);
    const sameFile = routers.get(routerKey(normalized, localName));
    if (sameFile && sameFile.declarationLine < useLine) return sameFile;
    const content = sourceByPath.get(normalized);
    if (!content) return undefined;
    const candidates = (importBindingsByPath.get(normalized) ?? []).filter((binding) => (
      binding.localName === localName
      && binding.edge.target
      && !bindingShadowedBeforeUse(content, binding, useLine)
    ));
    if (candidates.length !== 1) return undefined;
    const binding = candidates[0];
    return binding?.edge.target ? routers.get(routerKey(binding.edge.target, binding.importedName)) : undefined;
  }

  const includeEdges: RouterIncludeEdge[] = [];
  for (const [path, content] of sourceByPath) {
    const lines = content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const parsed = parseInclude(lines[index] ?? "");
      if (!parsed) continue;
      const line = index + 1;
      const child = resolveRouter(path, parsed.childName, line);
      if (!child) continue;
      const parent = parsed.parentName ? resolveRouter(path, parsed.parentName, line) : undefined;
      if (parsed.parentName && !parent) continue;
      includeEdges.push({ ...(parent ? { parent } : {}), child, prefix: parsed.prefix });
    }
  }

  const routesByRouter = new Map<string, RouteEntrypoint[]>();
  for (const entrypoint of entrypoints) {
    const path = normalizePath(entrypoint.route.path);
    const content = sourceByPath.get(path);
    if (!content) continue;
    const decorator = content.split(/\r?\n/)[entrypoint.route.line - 1] ?? "";
    const match = decorator.match(/^\s*@([A-Za-z_][A-Za-z0-9_]*)\.(?:get|post|put|patch|delete|options|head|route)\s*\(/i);
    const routerName = match?.[1];
    if (!routerName || routerName === "app") continue;
    const router = routers.get(routerKey(path, routerName));
    if (!router || router.declarationLine >= entrypoint.route.line) continue;
    const key = routerKey(router.path, router.name);
    routesByRouter.set(key, [...(routesByRouter.get(key) ?? []), entrypoint]);
  }

  const roots = includeEdges.filter((edge) => edge.parent === undefined);
  const childEdges = new Map<string, RouterIncludeEdge[]>();
  for (const edge of includeEdges) {
    if (!edge.parent) continue;
    const key = routerKey(edge.parent.path, edge.parent.name);
    childEdges.set(key, [...(childEdges.get(key) ?? []), edge]);
  }

  const composed: RouteEntrypoint[] = [];
  const composedKeys = new Set<string>();

  function appendRoutes(router: RouterNode, prefixes: string[], depth: number, rootPath: string, seen: ReadonlySet<string>): void {
    if (composed.length >= maxComposedRoutes || depth > maxIncludeDepth) return;
    const key = routerKey(router.path, router.name);
    if (seen.has(key)) return;
    const nextSeen = new Set(seen);
    nextSeen.add(key);
    const effectivePrefixes = [...prefixes, router.prefix].filter(Boolean);

    for (const entrypoint of routesByRouter.get(key) ?? []) {
      if (composed.length >= maxComposedRoutes) return;
      const route = composeRoute([...effectivePrefixes, entrypoint.route.route]);
      const candidate: FastApiComposedRouteEntrypoint = {
        ...entrypoint,
        route: {
          ...entrypoint.route,
          route,
          frameworkHint: "FastAPI composed router",
        },
        composition: {
          rootPath,
          includeDepth: depth,
          routerPath: router.path,
          routerName: router.name,
          prefixes: effectivePrefixes,
        },
        compositionInterpretation: "structural-fastapi-router-composition-not-runtime-reachability",
      };
      const candidateKey = routeKey(candidate);
      if (!composedKeys.has(candidateKey)) {
        composedKeys.add(candidateKey);
        composed.push(candidate);
      }
    }

    for (const edge of childEdges.get(key) ?? []) {
      appendRoutes(edge.child, [...effectivePrefixes, edge.prefix].filter(Boolean), depth + 1, rootPath, nextSeen);
    }
  }

  for (const root of roots) {
    if (composed.length >= maxComposedRoutes) break;
    appendRoutes(root.child, root.prefix ? [root.prefix] : [], 1, root.child.path, new Set());
  }

  const existingKeys = new Set(entrypoints.map(routeKey));
  return [...entrypoints, ...composed.filter((entrypoint) => !existingKeys.has(routeKey(entrypoint)))];
}
