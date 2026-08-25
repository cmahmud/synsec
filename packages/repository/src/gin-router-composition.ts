import { lstat, readFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, relative, resolve, sep } from "node:path";
import type { IndexFileInput, RouteSignal } from "./analysis.js";
import { findCallNeighborhood, type CallGraph, type CallGraphNode } from "./call-graph.js";
import type { RouteEntrypoint } from "./route-entrypoints.js";

const MAX_SOURCE_BYTES = 512_000;
const DEFAULT_MAX_ROUTES = 2_000;
const MAX_ROUTES = 10_000;
const MAX_GROUP_DEPTH = 12;

const HTTP_METHODS = new Map([
  ["GET", "GET"],
  ["POST", "POST"],
  ["PUT", "PUT"],
  ["PATCH", "PATCH"],
  ["DELETE", "DELETE"],
  ["OPTIONS", "OPTIONS"],
  ["HEAD", "HEAD"],
]);

interface GinScope {
  name: string;
  line: number;
  prefix: string;
  middleware: string[];
  depth: number;
}

export interface GinRouteMiddlewareContext {
  route: RouteSignal;
  scope: {
    name: string;
    line: number;
    prefix: string;
    depth: number;
  };
  handler: string;
  middleware: Array<{ name: string; source: "group" | "route"; line: number }>;
  /** Syntax-level Gin attachment only; this does not prove middleware executes or protects a request. */
  interpretation: "structural-gin-route-middleware-attachment-not-runtime-protection";
}

export interface GinRouterCompositionResult {
  entrypoints: RouteEntrypoint[];
  middlewareContexts: GinRouteMiddlewareContext[];
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

function normalizeRoute(value: string): string {
  const segments = value.split("/").filter(Boolean);
  return segments.length === 0 ? "" : `/${segments.join("/")}`;
}

function composeRoute(prefix: string, child: string): string {
  const segments = [prefix, child].flatMap((value) => value.split("/").filter(Boolean));
  return segments.length === 0 ? "/" : `/${segments.join("/")}`;
}

async function safeReadSource(rootPath: string, file: IndexFileInput): Promise<string | undefined> {
  if (extname(file.path).toLowerCase() !== ".go") return undefined;
  if (!file.path || file.path.includes("\0") || isAbsolute(file.path)) return undefined;
  const root = resolve(rootPath);
  const candidate = resolve(root, file.path);
  if (!insideRoot(root, candidate)) return undefined;
  const info = await lstat(candidate).catch(() => undefined);
  if (!info?.isFile() || info.isSymbolicLink() || info.size > MAX_SOURCE_BYTES) return undefined;
  const content = await readFile(candidate, "utf8").catch(() => undefined);
  return content?.includes("\u0000") ? undefined : content;
}

function hasUnaliasedGinImport(lines: readonly string[]): boolean {
  let inImportBlock = false;
  let imports = 0;
  for (const line of lines) {
    if (/^\s*import\s*\(\s*$/.test(line)) {
      inImportBlock = true;
      continue;
    }
    if (inImportBlock && /^\s*\)\s*$/.test(line)) {
      inImportBlock = false;
      continue;
    }
    if (/^\s*import\s+"github\.com\/gin-gonic\/gin"\s*$/.test(line)) {
      imports += 1;
      continue;
    }
    if (inImportBlock && /^\s*"github\.com\/gin-gonic\/gin"\s*$/.test(line)) {
      imports += 1;
      continue;
    }
    if (/github\.com\/gin-gonic\/gin/.test(line)) return false;
  }
  return imports === 1;
}

function parsePlainArguments(value: string): string[] | undefined {
  if (!value.trim()) return [];
  const args = value.split(",").map((part) => part.trim());
  if (args.some((arg) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(arg))) return undefined;
  return args;
}

function localHandler(graph: CallGraph, path: string, name: string): CallGraphNode | undefined {
  const matches = graph.nodes.filter(
    (node) => normalizePath(node.path) === path && node.kind === "go-function" && node.name === name,
  );
  return matches.length === 1 ? matches[0] : undefined;
}

function samePackageHandler(graph: CallGraph, path: string, name: string): CallGraphNode | undefined {
  const directory = dirname(path).replaceAll("\\", "/");
  const matches = graph.nodes.filter((node) => {
    if (node.kind !== "go-function" || node.name !== name) return false;
    return dirname(normalizePath(node.path)).replaceAll("\\", "/") === directory;
  });
  return matches.length === 1 ? matches[0] : undefined;
}

function routeKey(entrypoint: RouteEntrypoint): string {
  return [normalizePath(entrypoint.route.path), entrypoint.route.line, entrypoint.route.method, entrypoint.route.route, entrypoint.route.handler ?? "", entrypoint.handler?.id ?? ""].join("\0");
}

function bindingReassigned(lines: readonly string[], name: string, declarationLine: number, useLine: number): boolean {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const assignment = new RegExp(`^\\s*${escaped}\\s*(?::=|=(?!=))`);
  for (let index = declarationLine; index < useLine - 1; index += 1) {
    if (assignment.test(lines[index] ?? "")) return true;
  }
  return false;
}

/**
 * Resolve a deliberately narrow subset of Gin router/group registrations into structural route
 * entrypoints. Accepted syntax requires one unaliased gin import, a direct `name := gin.Default()`
 * or `gin.New()` root, literal `Group("/prefix", plainMiddleware...)` composition, and one-line HTTP
 * registrations whose callbacks are plain identifiers. The final callback is the handler; preceding
 * callbacks plus inherited group callbacks are retained only as review-level middleware attachment.
 *
 * Handler resolution is limited to one unique Go function in the same package directory. Dynamic
 * prefixes, aliases, factories, member-expression handlers, transformed middleware, reassigned scope
 * bindings, ambiguous functions, unsafe files, and over-deep group composition fail closed. This does
 * not prove Gin registers or serves the route, middleware executes, input is attacker-controlled, or
 * a finding is exploitable.
 */
export async function composeGinRouterEntrypoints(
  rootPath: string,
  files: readonly IndexFileInput[],
  graph: CallGraph,
  entrypoints: readonly RouteEntrypoint[],
  options: { maxRoutes?: number; maxCallDepth?: number; maxCallNodes?: number } = {},
): Promise<GinRouterCompositionResult> {
  const maxRoutes = boundedInteger(options.maxRoutes, DEFAULT_MAX_ROUTES, MAX_ROUTES, "Gin maxRoutes");
  const maxCallDepth = Math.max(0, Math.min(20, options.maxCallDepth ?? 3));
  const maxCallNodes = Math.max(1, Math.min(1_000, options.maxCallNodes ?? 100));
  const output = [...entrypoints];
  const existing = new Set(output.map(routeKey));
  const middlewareContexts: GinRouteMiddlewareContext[] = [];
  let produced = 0;

  for (const file of files) {
    if (produced >= maxRoutes) break;
    const content = await safeReadSource(rootPath, file);
    if (content === undefined) continue;
    const lines = content.split(/\r?\n/);
    if (!hasUnaliasedGinImport(lines)) continue;
    const path = normalizePath(file.path);
    const scopes = new Map<string, GinScope>();

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index] ?? "";
      const rootMatch = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:=\s*gin\.(?:Default|New)\s*\(\s*\)\s*$/);
      if (rootMatch?.[1]) {
        if (scopes.has(rootMatch[1])) scopes.delete(rootMatch[1]);
        else scopes.set(rootMatch[1], { name: rootMatch[1], line: index + 1, prefix: "", middleware: [], depth: 0 });
        continue;
      }

      const groupMatch = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:=\s*([A-Za-z_][A-Za-z0-9_]*)\.Group\s*\(\s*"([^"]*)"\s*(?:,\s*(.*?))?\s*\)\s*$/);
      if (!groupMatch?.[1] || !groupMatch[2] || groupMatch[3] === undefined) continue;
      const parent = scopes.get(groupMatch[2]);
      if (!parent || parent.line >= index + 1 || parent.depth >= MAX_GROUP_DEPTH || bindingReassigned(lines, parent.name, parent.line, index + 1)) continue;
      const middleware = parsePlainArguments(groupMatch[4] ?? "");
      if (!middleware) continue;
      if (scopes.has(groupMatch[1])) {
        scopes.delete(groupMatch[1]);
        continue;
      }
      scopes.set(groupMatch[1], {
        name: groupMatch[1],
        line: index + 1,
        prefix: composeRoute(parent.prefix, normalizeRoute(groupMatch[3])),
        middleware: [...parent.middleware, ...middleware],
        depth: parent.depth + 1,
      });
    }

    for (let index = 0; index < lines.length && produced < maxRoutes; index += 1) {
      const line = lines[index] ?? "";
      const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\.(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s*\(\s*"([^"]*)"\s*,\s*(.*?)\s*\)\s*$/);
      if (!match?.[1] || !match[2] || match[3] === undefined || match[4] === undefined) continue;
      const scope = scopes.get(match[1]);
      if (!scope || scope.line >= index + 1 || bindingReassigned(lines, scope.name, scope.line, index + 1)) continue;
      const method = HTTP_METHODS.get(match[2]);
      if (!method) continue;
      const callbacks = parsePlainArguments(match[4]);
      if (!callbacks || callbacks.length === 0) continue;
      const handlerName = callbacks.at(-1);
      if (!handlerName) continue;
      const routeMiddleware = callbacks.slice(0, -1);
      const route: RouteSignal = {
        path,
        line: index + 1,
        method,
        route: composeRoute(scope.prefix, normalizeRoute(match[3])),
        frameworkHint: "Gin router",
        handler: handlerName,
      };
      const handler = localHandler(graph, path, handlerName) ?? samePackageHandler(graph, path, handlerName);
      const entrypoint: RouteEntrypoint = handler
        ? {
            route,
            resolution: "named-function",
            handler,
            calls: findCallNeighborhood(graph, handler.id, maxCallDepth, maxCallNodes),
            interpretation: "structural-route-call-evidence-only",
          }
        : {
            route,
            resolution: "unresolved",
            interpretation: "structural-route-call-evidence-only",
          };
      const key = routeKey(entrypoint);
      if (existing.has(key)) continue;
      existing.add(key);
      output.push(entrypoint);
      produced += 1;

      const middleware = [
        ...scope.middleware.map((name) => ({ name, source: "group" as const, line: scope.line })),
        ...routeMiddleware.map((name) => ({ name, source: "route" as const, line: index + 1 })),
      ];
      if (middleware.length > 0) {
        middlewareContexts.push({
          route,
          scope: { name: scope.name, line: scope.line, prefix: scope.prefix, depth: scope.depth },
          handler: handlerName,
          middleware,
          interpretation: "structural-gin-route-middleware-attachment-not-runtime-protection",
        });
      }
    }
  }

  return { entrypoints: output, middlewareContexts };
}
