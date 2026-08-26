import { lstat, readFile } from "node:fs/promises";
import { extname, isAbsolute, relative, resolve, sep } from "node:path";
import type { IndexFileInput, RouteSignal } from "./analysis.js";
import { findCallNeighborhood, type CallGraph, type CallGraphNode } from "./call-graph.js";
import type { RouteEntrypoint } from "./route-entrypoints.js";

const MAX_SOURCE_BYTES = 512_000;
const DEFAULT_MAX_ROUTES = 2_000;
const MAX_ROUTES = 10_000;

const HTTP_METHODS = new Map([
  ["get", "GET"],
  ["post", "POST"],
  ["put", "PUT"],
  ["patch", "PATCH"],
  ["delete", "DELETE"],
  ["options", "OPTIONS"],
  ["head", "HEAD"],
]);

interface RouterDeclaration {
  name: string;
  line: number;
  prefix: string;
}

export interface KoaRouteMiddlewareContext {
  route: RouteSignal;
  router: {
    name: string;
    line: number;
    prefix: string;
  };
  handler: string;
  middleware: Array<{ name: string; line: number }>;
  /** Syntax-level router attachment only; this does not prove middleware executes or protects a request. */
  interpretation: "structural-koa-route-middleware-attachment-not-runtime-protection";
}

export interface KoaRouterCompositionResult {
  entrypoints: RouteEntrypoint[];
  middlewareContexts: KoaRouteMiddlewareContext[];
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
  const extension = extname(file.path).toLowerCase();
  if (![".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"].includes(extension)) return undefined;
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

function routerImportLine(line: string): boolean {
  return /^\s*import\s+Router\s+from\s+["'](?:@koa\/router|koa-router)["']\s*;?\s*$/.test(line)
    || /^\s*const\s+Router\s*=\s*require\s*\(\s*["'](?:@koa\/router|koa-router)["']\s*\)\s*;?\s*$/.test(line);
}

function hasSingleUnshadowedRouterImport(lines: readonly string[], useLine: number): boolean {
  const imports: number[] = [];
  for (let index = 0; index < Math.min(lines.length, useLine - 1); index += 1) {
    if (routerImportLine(lines[index] ?? "")) imports.push(index + 1);
  }
  if (imports.length !== 1) return false;
  const importLine = imports[0];
  if (!importLine) return false;
  for (let index = importLine; index < useLine - 1; index += 1) {
    const line = lines[index] ?? "";
    if (/^\s*(?:const|let|var|function|class)\s+Router\b/.test(line) || /^\s*Router\s*=(?!=)/.test(line)) return false;
  }
  return true;
}

function parseRouterDeclaration(line: string, lineNumber: number): RouterDeclaration | undefined {
  const empty = line.match(/^\s*const\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+Router\s*\(\s*\)\s*;?\s*$/);
  if (empty?.[1]) return { name: empty[1], line: lineNumber, prefix: "" };
  const prefixed = line.match(/^\s*const\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+Router\s*\(\s*\{\s*prefix\s*:\s*(["'])([^"']*)\2\s*\}\s*\)\s*;?\s*$/);
  if (!prefixed?.[1] || prefixed[3] === undefined) return undefined;
  return { name: prefixed[1], line: lineNumber, prefix: normalizeRoute(prefixed[3]) };
}

function routerBindingStillValid(lines: readonly string[], declaration: RouterDeclaration, useLine: number): boolean {
  const escaped = escapeIdentifier(declaration.name);
  const declarationPattern = new RegExp(`^\\s*(?:const|let|var|function|class)\\s+${escaped}\\b`);
  const assignmentPattern = new RegExp(`^\\s*${escaped}\\s*=(?!=)`);
  for (let index = declaration.line; index < useLine - 1; index += 1) {
    const line = lines[index] ?? "";
    if (declarationPattern.test(line) || assignmentPattern.test(line)) return false;
  }
  return true;
}

function parsePlainArguments(value: string): string[] | undefined {
  const args = value.split(",").map((part) => part.trim());
  if (args.length === 0 || args.some((arg) => !/^[A-Za-z_$][\w$]*$/.test(arg))) return undefined;
  return args;
}

function localHandler(graph: CallGraph, path: string, name: string): CallGraphNode | undefined {
  const matches = graph.nodes.filter((node) => normalizePath(node.path) === path && node.name === name);
  return matches.length === 1 ? matches[0] : undefined;
}

function routeKey(entrypoint: RouteEntrypoint): string {
  return [normalizePath(entrypoint.route.path), entrypoint.route.line, entrypoint.route.method, entrypoint.route.route, entrypoint.route.frameworkHint ?? "", entrypoint.route.handler ?? "", entrypoint.handler?.id ?? ""].join("\0");
}

/**
 * Resolve a deliberately narrow subset of Koa router registrations into structural route entrypoints.
 *
 * Accepted syntax requires exactly one unaliased `Router` import/require from `@koa/router` or the
 * legacy `koa-router` package, a `const router = new Router()` declaration with an optional literal
 * `{ prefix: "..." }`, and a one-line HTTP registration whose callback arguments are all plain
 * identifiers. The final identifier is treated as the handler and preceding identifiers are retained
 * as review-only middleware attachment evidence. Same-file handlers resolve immediately; unresolved
 * named handlers remain eligible for SynSec's existing repository-local named-import resolver.
 *
 * Dynamic prefixes, router factories, member-expression callbacks, inline callbacks, transformed
 * middleware, reassigned router bindings, ambiguous handlers, unsafe files, and unsupported syntax
 * fail closed. This does not prove Koa mounts the router, middleware executes, a route is externally
 * reachable, input is attacker-controlled, or a finding is exploitable.
 */
export async function composeKoaRouterEntrypoints(
  rootPath: string,
  files: readonly IndexFileInput[],
  graph: CallGraph,
  entrypoints: readonly RouteEntrypoint[],
  options: { maxRoutes?: number; maxCallDepth?: number; maxCallNodes?: number } = {},
): Promise<KoaRouterCompositionResult> {
  const maxRoutes = boundedInteger(options.maxRoutes, DEFAULT_MAX_ROUTES, MAX_ROUTES, "Koa maxRoutes");
  const maxCallDepth = Math.max(0, Math.min(20, options.maxCallDepth ?? 3));
  const maxCallNodes = Math.max(1, Math.min(1_000, options.maxCallNodes ?? 100));
  const output = [...entrypoints];
  const existing = new Set(output.map(routeKey));
  const middlewareContexts: KoaRouteMiddlewareContext[] = [];
  let produced = 0;

  for (const file of files) {
    if (produced >= maxRoutes) break;
    const content = await safeReadSource(rootPath, file);
    if (content === undefined) continue;
    const path = normalizePath(file.path);
    const lines = content.split(/\r?\n/);
    const routers = new Map<string, RouterDeclaration>();

    for (let index = 0; index < lines.length; index += 1) {
      const declaration = parseRouterDeclaration(lines[index] ?? "", index + 1);
      if (!declaration || !hasSingleUnshadowedRouterImport(lines, declaration.line)) continue;
      if (routers.has(declaration.name)) routers.delete(declaration.name);
      else routers.set(declaration.name, declaration);
    }

    for (let index = 0; index < lines.length && produced < maxRoutes; index += 1) {
      const line = lines[index] ?? "";
      const match = line.match(/^\s*([A-Za-z_$][\w$]*)\.(get|post|put|patch|delete|options|head)\s*\(\s*(["'])([^"']*)\3\s*,\s*(.*?)\s*\)\s*;?\s*$/i);
      if (!match?.[1] || !match[2] || match[4] === undefined || match[5] === undefined) continue;
      const router = routers.get(match[1]);
      if (!router || router.line >= index + 1 || !routerBindingStillValid(lines, router, index + 1)) continue;
      const httpMethod = HTTP_METHODS.get(match[2].toLowerCase());
      if (!httpMethod) continue;
      const callbacks = parsePlainArguments(match[5]);
      if (!callbacks || callbacks.length === 0) continue;
      const handlerName = callbacks.at(-1);
      if (!handlerName) continue;
      const middlewareNames = callbacks.slice(0, -1);
      const route: RouteSignal = {
        path,
        line: index + 1,
        method: httpMethod,
        route: composeRoute(router.prefix, normalizeRoute(match[4])),
        frameworkHint: "Koa router",
        handler: handlerName,
      };
      const handler = localHandler(graph, path, handlerName);
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

      if (middlewareNames.length > 0) {
        middlewareContexts.push({
          route,
          router: { name: router.name, line: router.line, prefix: router.prefix },
          handler: handlerName,
          middleware: middlewareNames.map((name) => ({ name, line: index + 1 })),
          interpretation: "structural-koa-route-middleware-attachment-not-runtime-protection",
        });
      }
    }
  }

  return { entrypoints: output, middlewareContexts };
}
