import { lstat, readFile } from "node:fs/promises";
import { extname, isAbsolute, relative, resolve, sep } from "node:path";
import type { IndexFileInput } from "./analysis.js";
import type { ModuleGraph, ResolvedModuleEdge } from "./module-graph.js";
import type { RouteEntrypoint } from "./route-entrypoints.js";

const MAX_SOURCE_BYTES = 512_000;
const JS_EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"]);
const DEFAULT_MAX_MOUNT_DEPTH = 8;
const MAX_MOUNT_DEPTH = 32;
const DEFAULT_MAX_COMPOSED_ROUTES = 2_000;
const MAX_COMPOSED_ROUTES = 10_000;

interface RouterNode { path: string; name: string; declarationLine: number; }
interface ImportedRouterBinding { localName: string; edge: ResolvedModuleEdge; }
interface RouterMountEdge { parent?: RouterNode; child: RouterNode; prefix: string; }

export interface ExpressComposedRouteEntrypoint extends RouteEntrypoint {
  composition: { rootPath: string; mountDepth: number; routerPath: string; routerName: string; prefixes: string[]; };
  compositionInterpretation: "structural-express-router-composition-not-runtime-reachability";
}

function normalizePath(value: string): string { return value.replaceAll("\\", "/").replace(/^\.\//, ""); }
function insideRoot(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}
function boundedInteger(value: number | undefined, fallback: number, maximum: number, label: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < 1 || resolved > maximum) throw new Error(`${label} must be an integer between 1 and ${maximum}.`);
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
function escapeIdentifier(value: string): string { return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
async function safeReadSource(rootPath: string, file: IndexFileInput): Promise<string | undefined> {
  if (!file.path || file.path.includes("\0") || isAbsolute(file.path) || !JS_EXTENSIONS.has(extname(file.path).toLowerCase())) return undefined;
  const root = resolve(rootPath);
  const candidate = resolve(root, file.path);
  if (!insideRoot(root, candidate)) return undefined;
  const info = await lstat(candidate).catch(() => undefined);
  if (!info?.isFile() || info.isSymbolicLink() || info.size > MAX_SOURCE_BYTES) return undefined;
  const content = await readFile(candidate, "utf8").catch(() => undefined);
  return content?.includes("\u0000") ? undefined : content;
}
function explicitExpressObjectBinding(content: string, beforeLine: number): boolean {
  const lines = content.split(/\r?\n/).slice(0, Math.max(0, beforeLine - 1));
  return lines.some((line) => /^\s*import\s+express\s+from\s+["']express["']\s*;?\s*$/.test(line)
    || /^\s*(?:const|let|var)\s+express\s*=\s*require\s*\(\s*["']express["']\s*\)\s*;?\s*$/.test(line));
}
function explicitRouterFactoryBinding(content: string, beforeLine: number): boolean {
  const lines = content.split(/\r?\n/).slice(0, Math.max(0, beforeLine - 1));
  return lines.some((line) => /^\s*import\s*\{\s*Router\s*\}\s*from\s*["']express["']\s*;?\s*$/.test(line)
    || /^\s*(?:const|let|var)\s*\{\s*Router\s*\}\s*=\s*require\s*\(\s*["']express["']\s*\)\s*;?\s*$/.test(line));
}
function parseRouterDeclaration(content: string, line: string, lineNumber: number): string | undefined {
  const objectFactory = line.match(/^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*express\.Router\s*\(\s*\)\s*;?\s*(?:\/\/.*)?$/);
  if (objectFactory?.[1] && explicitExpressObjectBinding(content, lineNumber)) return objectFactory[1];
  const namedFactory = line.match(/^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*Router\s*\(\s*\)\s*;?\s*(?:\/\/.*)?$/);
  return namedFactory?.[1] && explicitRouterFactoryBinding(content, lineNumber) ? namedFactory[1] : undefined;
}
function parseAppDeclaration(content: string, line: string, lineNumber: number): string | undefined {
  const match = line.match(/^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*express\s*\(\s*\)\s*;?\s*(?:\/\/.*)?$/);
  return match?.[1] && explicitExpressObjectBinding(content, lineNumber) ? match[1] : undefined;
}
function exportedAsDefault(content: string, routerName: string): boolean {
  const escaped = escapeIdentifier(routerName);
  return new RegExp(`^\\s*export\\s+default\\s+${escaped}\\s*;?\\s*$`, "m").test(content)
    || new RegExp(`^\\s*module\\.exports\\s*=\\s*${escaped}\\s*;?\\s*$`, "m").test(content);
}
function parseImportedBinding(line: string, edge: ResolvedModuleEdge): ImportedRouterBinding | undefined {
  if (edge.resolution !== "repository-file" || !edge.target) return undefined;
  const specifier = escapeIdentifier(edge.specifier);
  const esm = line.match(new RegExp(`^\\s*import\\s+([A-Za-z_$][\\w$]*)\\s+from\\s+["']${specifier}["']\\s*;?\\s*$`));
  if (esm?.[1]) return { localName: esm[1], edge };
  const cjs = line.match(new RegExp(`^\\s*(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*require\\s*\\(\\s*["']${specifier}["']\\s*\\)\\s*;?\\s*$`));
  return cjs?.[1] ? { localName: cjs[1], edge } : undefined;
}
function bindingShadowedBeforeUse(content: string, binding: ImportedRouterBinding, useLine: number): boolean {
  if (useLine <= binding.edge.line) return true;
  const escaped = escapeIdentifier(binding.localName);
  const lines = content.split(/\r?\n/).slice(binding.edge.line, useLine - 1);
  const declaration = new RegExp(`^\\s*(?:const|let|var|function|class)\\s+${escaped}\\b`);
  const assignment = new RegExp(`^\\s*${escaped}\\s*=(?!=)`);
  return lines.some((line) => declaration.test(line) || assignment.test(line));
}
function parseMount(line: string): { parentName: string; childName: string; prefix: string } | undefined {
  const match = line.match(/^\s*([A-Za-z_$][\w$]*)\.use\s*\(\s*(["'])([^"']*)\2\s*,\s*([A-Za-z_$][\w$]*)\s*\)\s*;?\s*(?:\/\/.*)?$/);
  if (!match?.[1] || !match[4]) return undefined;
  return { parentName: match[1], childName: match[4], prefix: normalizePrefix(match[3] ?? "") };
}
function routerKey(path: string, name: string): string { return `${normalizePath(path)}\0${name}`; }
function routeKey(entrypoint: RouteEntrypoint): string {
  return [normalizePath(entrypoint.route.path), entrypoint.route.line, entrypoint.route.method, entrypoint.route.route, entrypoint.handler?.id ?? ""].join("\0");
}

export async function composeExpressRouterEntrypoints(
  rootPath: string,
  files: readonly IndexFileInput[],
  moduleGraph: ModuleGraph,
  entrypoints: readonly RouteEntrypoint[],
  options: { maxMountDepth?: number; maxComposedRoutes?: number } = {},
): Promise<RouteEntrypoint[]> {
  const maxMountDepth = boundedInteger(options.maxMountDepth, DEFAULT_MAX_MOUNT_DEPTH, MAX_MOUNT_DEPTH, "Express router maxMountDepth");
  const maxComposedRoutes = boundedInteger(options.maxComposedRoutes, DEFAULT_MAX_COMPOSED_ROUTES, MAX_COMPOSED_ROUTES, "Express router maxComposedRoutes");
  const sourceByPath = new Map<string, string>();
  for (const file of files) { const source = await safeReadSource(rootPath, file); if (source !== undefined) sourceByPath.set(normalizePath(file.path), source); }
  const routers = new Map<string, RouterNode>();
  const ambiguousRouters = new Set<string>();
  const apps = new Map<string, Set<string>>();
  for (const [path, content] of sourceByPath) {
    const lines = content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const routerName = parseRouterDeclaration(content, lines[index] ?? "", index + 1);
      if (routerName) {
        const key = routerKey(path, routerName);
        if (routers.has(key)) { routers.delete(key); ambiguousRouters.add(key); }
        else if (!ambiguousRouters.has(key)) routers.set(key, { path, name: routerName, declarationLine: index + 1 });
      }
      const appName = parseAppDeclaration(content, lines[index] ?? "", index + 1);
      if (appName) apps.set(path, new Set([...(apps.get(path) ?? []), appName]));
    }
  }
  const importsByPath = new Map<string, ImportedRouterBinding[]>();
  for (const edge of moduleGraph.edges) {
    if ((edge.kind !== "import" && edge.kind !== "require") || edge.resolution !== "repository-file" || !edge.target) continue;
    const path = normalizePath(edge.from);
    const content = sourceByPath.get(path);
    if (!content) continue;
    const binding = parseImportedBinding(content.split(/\r?\n/)[edge.line - 1] ?? "", edge);
    if (binding) importsByPath.set(path, [...(importsByPath.get(path) ?? []), binding]);
  }
  function resolveRouter(path: string, localName: string, useLine: number): RouterNode | undefined {
    const normalized = normalizePath(path);
    const sameFile = routers.get(routerKey(normalized, localName));
    if (sameFile && sameFile.declarationLine < useLine) return sameFile;
    const content = sourceByPath.get(normalized);
    if (!content) return undefined;
    const candidates = (importsByPath.get(normalized) ?? []).filter((binding) => binding.localName === localName && !bindingShadowedBeforeUse(content, binding, useLine));
    if (candidates.length !== 1) return undefined;
    const targetPath = candidates[0]?.edge.target;
    const targetContent = targetPath ? sourceByPath.get(normalizePath(targetPath)) : undefined;
    if (!targetPath || !targetContent) return undefined;
    const exported = [...routers.values()].filter((router) => normalizePath(router.path) === normalizePath(targetPath) && exportedAsDefault(targetContent, router.name));
    return exported.length === 1 ? exported[0] : undefined;
  }
  const mounts: RouterMountEdge[] = [];
  for (const [path, content] of sourceByPath) {
    const lines = content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const parsed = parseMount(lines[index] ?? "");
      if (!parsed) continue;
      const line = index + 1;
      const child = resolveRouter(path, parsed.childName, line);
      if (!child) continue;
      const isApp = apps.get(path)?.has(parsed.parentName) === true;
      const parent = isApp ? undefined : resolveRouter(path, parsed.parentName, line);
      if (isApp || parent) mounts.push({ ...(parent ? { parent } : {}), child, prefix: parsed.prefix });
    }
  }
  const routesByRouter = new Map<string, RouteEntrypoint[]>();
  for (const entrypoint of entrypoints) {
    if (entrypoint.route.frameworkHint !== "Node HTTP router" || entrypoint.route.method === "USE") continue;
    const path = normalizePath(entrypoint.route.path);
    const content = sourceByPath.get(path);
    if (!content) continue;
    const receiver = content.split(/\r?\n/)[entrypoint.route.line - 1]?.match(/^\s*([A-Za-z_$][\w$]*)\.(?:get|post|put|patch|delete|options|head)\s*\(/i)?.[1];
    if (!receiver) continue;
    const router = routers.get(routerKey(path, receiver));
    if (!router || router.declarationLine >= entrypoint.route.line) continue;
    routesByRouter.set(routerKey(router.path, router.name), [...(routesByRouter.get(routerKey(router.path, router.name)) ?? []), entrypoint]);
  }
  const output: RouteEntrypoint[] = [...entrypoints];
  const seen = new Set(output.map(routeKey));
  const walk = (router: RouterNode, prefixes: string[], depth: number, stack: Set<string>, rootPath: string): void => {
    if (depth > maxMountDepth || output.length - entrypoints.length >= maxComposedRoutes) return;
    const key = routerKey(router.path, router.name);
    if (stack.has(key)) return;
    const nextStack = new Set(stack).add(key);
    for (const entrypoint of routesByRouter.get(key) ?? []) {
      const composed: ExpressComposedRouteEntrypoint = {
        ...entrypoint,
        route: { ...entrypoint.route, route: composeRoute([...prefixes, entrypoint.route.route]), frameworkHint: "Express composed router" },
        composition: { rootPath, mountDepth: depth, routerPath: router.path, routerName: router.name, prefixes: [...prefixes] },
        compositionInterpretation: "structural-express-router-composition-not-runtime-reachability",
      };
      const keyValue = routeKey(composed);
      if (!seen.has(keyValue)) { seen.add(keyValue); output.push(composed); }
      if (output.length - entrypoints.length >= maxComposedRoutes) return;
    }
    if (depth >= maxMountDepth) return;
    for (const mount of mounts) {
      if (mount.parent && routerKey(mount.parent.path, mount.parent.name) === key) walk(mount.child, [...prefixes, mount.prefix], depth + 1, nextStack, rootPath);
    }
  };
  for (const root of mounts.filter((mount) => !mount.parent)) {
    walk(root.child, [root.prefix], 1, new Set(), root.child.path);
    if (output.length - entrypoints.length >= maxComposedRoutes) break;
  }
  return output;
}
