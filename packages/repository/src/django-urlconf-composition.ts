import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { IndexFileInput, RouteSignal } from "./analysis.js";
import type { RouteEntrypoint } from "./route-entrypoints.js";

const MAX_SOURCE_BYTES = 512_000;
const DEFAULT_MAX_INCLUDE_DEPTH = 4;
const MAX_INCLUDE_DEPTH = 12;
const DEFAULT_MAX_COMPOSED_ROUTES = 1_000;
const MAX_COMPOSED_ROUTES = 5_000;

interface DjangoIncludeEdge {
  fromPath: string;
  line: number;
  prefix: string;
  targetPath: string;
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

function boundedInteger(value: number | undefined, fallback: number, maximum: number, label: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < 1 || resolved > maximum) {
    throw new Error(`${label} must be an integer between 1 and ${maximum}.`);
  }
  return resolved;
}

function explicitInclude(line: string): { prefix: string; module: string } | undefined {
  const match = line.match(
    /\bpath\s*\(\s*["']([^"']*)["']\s*,\s*include\s*\(\s*["']([A-Za-z_][A-Za-z0-9_.]*)["']\s*\)\s*(?:,|\))?/,
  );
  if (match?.[1] === undefined || !match[2]) return undefined;
  return { prefix: match[1], module: match[2] };
}

function resolveLiteralModule(moduleName: string, filePaths: ReadonlySet<string>): string | undefined {
  const stem = moduleName.split(".").join("/");
  const candidates = [`${stem}.py`, `${stem}/__init__.py`].filter((candidate) => filePaths.has(candidate));
  return candidates.length === 1 ? candidates[0] : undefined;
}

function joinRoute(prefix: string, child: string): string {
  const left = prefix.replace(/^\/+/, "");
  const right = child.replace(/^\/+/, "");
  if (!left) return right || "/";
  if (!right) return left;
  if (left.endsWith("/")) return `${left}${right}`;
  return `${left}/${right}`;
}

function composedRoute(route: RouteSignal, prefix: string): RouteSignal {
  return {
    ...route,
    route: joinRoute(prefix, route.route),
    frameworkHint: "Django URLConf include",
  };
}

function entrypointKey(entrypoint: RouteEntrypoint): string {
  return [
    normalizePath(entrypoint.route.path),
    entrypoint.route.line,
    entrypoint.route.method,
    entrypoint.route.route,
    entrypoint.route.frameworkHint ?? "unknown-framework",
    entrypoint.handler?.id ?? "unresolved",
  ].join(":");
}

/**
 * Add structural route identities for explicit Django `path("prefix/", include("module.urls"))`
 * composition without importing or executing repository Python code.
 *
 * Only literal module strings that map to exactly one supplied repository file are followed. Include
 * graphs are traversed from structurally root URLConfs (files not themselves targeted by another
 * resolved include). Cycles, ambiguous module files, dynamic include expressions, tuple/list URLConfs,
 * callable include targets, path converters built dynamically, and graphs without a structural root
 * produce no composed evidence. Existing direct entrypoints are retained because static repository
 * analysis cannot prove which URLConf is configured as Django's runtime ROOT_URLCONF.
 *
 * A composed route remains static structural evidence only. It does not prove ROOT_URLCONF selection,
 * `include()` execution, namespace behavior, middleware execution, runtime reachability, attacker
 * control, authorization, or exploitability.
 */
export async function composeDjangoIncludedRouteEntrypoints(
  rootPath: string,
  files: readonly IndexFileInput[],
  entrypoints: readonly RouteEntrypoint[],
  options: { maxIncludeDepth?: number; maxComposedRoutes?: number } = {},
): Promise<RouteEntrypoint[]> {
  const maxIncludeDepth = boundedInteger(
    options.maxIncludeDepth,
    DEFAULT_MAX_INCLUDE_DEPTH,
    MAX_INCLUDE_DEPTH,
    "Django include max depth",
  );
  const maxComposedRoutes = boundedInteger(
    options.maxComposedRoutes,
    DEFAULT_MAX_COMPOSED_ROUTES,
    MAX_COMPOSED_ROUTES,
    "Django include max composed routes",
  );
  const pythonFiles = files.filter((file) => normalizePath(file.path).endsWith(".py"));
  const filePaths = new Set(pythonFiles.map((file) => normalizePath(file.path)));
  const edges: DjangoIncludeEdge[] = [];

  for (const file of pythonFiles) {
    const fromPath = normalizePath(file.path);
    const content = await safeReadSource(rootPath, file);
    if (!content) continue;
    const lines = content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const include = explicitInclude(lines[index] ?? "");
      if (!include) continue;
      const targetPath = resolveLiteralModule(include.module, filePaths);
      if (!targetPath || targetPath === fromPath) continue;
      edges.push({ fromPath, line: index + 1, prefix: include.prefix, targetPath });
    }
  }

  if (edges.length === 0) return [...entrypoints];

  const targetPaths = new Set(edges.map((edge) => edge.targetPath));
  const roots = [...new Set(edges.map((edge) => edge.fromPath).filter((path) => !targetPaths.has(path)))].sort();
  if (roots.length === 0) return [...entrypoints];

  const edgesBySource = new Map<string, DjangoIncludeEdge[]>();
  for (const edge of edges) {
    const bucket = edgesBySource.get(edge.fromPath) ?? [];
    bucket.push(edge);
    bucket.sort((a, b) => a.line - b.line || a.prefix.localeCompare(b.prefix) || a.targetPath.localeCompare(b.targetPath));
    edgesBySource.set(edge.fromPath, bucket);
  }

  const directByPath = new Map<string, RouteEntrypoint[]>();
  for (const entrypoint of entrypoints) {
    if (entrypoint.resolution === "unresolved" || !entrypoint.handler) continue;
    if (entrypoint.route.frameworkHint !== "Django URLConf") continue;
    const path = normalizePath(entrypoint.route.path);
    const bucket = directByPath.get(path) ?? [];
    bucket.push(entrypoint);
    directByPath.set(path, bucket);
  }

  const output = [...entrypoints];
  const seen = new Set(output.map(entrypointKey));
  let composedCount = 0;

  function addFrom(
    sourcePath: string,
    prefix: string,
    depth: number,
    ancestry: ReadonlySet<string>,
  ): void {
    if (depth > maxIncludeDepth || composedCount >= maxComposedRoutes) return;
    for (const edge of edgesBySource.get(sourcePath) ?? []) {
      if (composedCount >= maxComposedRoutes || ancestry.has(edge.targetPath)) continue;
      const nextPrefix = joinRoute(prefix, edge.prefix);
      for (const child of directByPath.get(edge.targetPath) ?? []) {
        if (composedCount >= maxComposedRoutes) break;
        const candidate: RouteEntrypoint = {
          ...child,
          route: composedRoute(child.route, nextPrefix),
        };
        const key = entrypointKey(candidate);
        if (seen.has(key)) continue;
        seen.add(key);
        output.push(candidate);
        composedCount += 1;
      }
      const nextAncestry = new Set(ancestry);
      nextAncestry.add(edge.targetPath);
      addFrom(edge.targetPath, nextPrefix, depth + 1, nextAncestry);
    }
  }

  for (const root of roots) {
    addFrom(root, "", 1, new Set([root]));
    if (composedCount >= maxComposedRoutes) break;
  }

  return output;
}
