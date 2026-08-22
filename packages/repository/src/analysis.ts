import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, extname, resolve } from "node:path";

export interface IndexFileInput {
  path: string;
  size: number;
}

export interface ModuleEdge {
  from: string;
  specifier: string;
  kind: "import" | "require" | "dynamic-import" | "python-import" | "go-import";
  line: number;
}

export interface RouteSignal {
  path: string;
  line: number;
  method: string;
  route: string;
  frameworkHint?: string;
  /** Conservative same-line named-handler candidate; never inferred from dynamic expressions. */
  handler?: string;
}

export interface AuthSignal {
  path: string;
  line: number;
  kind: "authentication" | "authorization" | "session" | "token";
  evidence: string;
}

export interface SinkSignal {
  path: string;
  line: number;
  kind: "process" | "filesystem" | "database" | "network";
  evidence: string;
}

export interface RepositoryIndex {
  schemaVersion: 1;
  generatedAt: string;
  indexedFileCount: number;
  moduleEdges: ModuleEdge[];
  routes: RouteSignal[];
  authSignals: AuthSignal[];
  sinks: SinkSignal[];
}

export interface DependencyUsage {
  packageName: string;
  status: "observed-import" | "unknown";
  evidence: ModuleEdge[];
}

export interface RouteSecurityContext {
  route: RouteSignal;
  nearbyAuthSignals: AuthSignal[];
  nearbySinks: SinkSignal[];
}

export interface NearbyRouteSignal {
  line: number;
  distance: number;
  method: string;
  route: string;
  frameworkHint?: string;
}

export interface NearbySecuritySignal {
  line: number;
  distance: number;
  kind: AuthSignal["kind"] | SinkSignal["kind"];
}

export interface FindingRepositoryContext {
  path: string;
  line?: number;
  radius: number;
  nearbyRoutes: NearbyRouteSignal[];
  nearbyAuthSignals: NearbySecuritySignal[];
  nearbySinks: NearbySecuritySignal[];
  /** These are lexical proximity signals, not proof of data flow or reachability. */
  interpretation: "proximity-signals-only";
}

const analyzableExtensions = new Set([
  ".js", ".mjs", ".cjs", ".jsx",
  ".ts", ".mts", ".cts", ".tsx",
  ".py", ".go", ".rb", ".php", ".java", ".kt", ".kts", ".cs",
]);

const MAX_INDEX_FILE_BYTES = 512_000;
const MAX_INDEX_FILES = 5_000;
const MAX_SIGNALS_PER_FILE = 500;

function sourceLine(lines: readonly string[], index: number): string {
  return (lines[index] ?? "").trim().slice(0, 300);
}

function collectModuleEdges(path: string, content: string): ModuleEdge[] {
  const edges: ModuleEdge[] = [];
  const lines = content.split(/\r?\n/);
  const extension = extname(path).toLowerCase();

  for (let index = 0; index < lines.length && edges.length < MAX_SIGNALS_PER_FILE; index += 1) {
    const line = lines[index] ?? "";
    const lineNumber = index + 1;

    if ([".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"].includes(extension)) {
      const staticImport = line.match(/\b(?:import|export)\s+(?:[^"']*?\s+from\s+)?["']([^"']+)["']/);
      if (staticImport?.[1]) edges.push({ from: path, specifier: staticImport[1], kind: "import", line: lineNumber });
      const requireCall = line.match(/\brequire\s*\(\s*["']([^"']+)["']\s*\)/);
      if (requireCall?.[1]) edges.push({ from: path, specifier: requireCall[1], kind: "require", line: lineNumber });
      const dynamicImport = line.match(/\bimport\s*\(\s*["']([^"']+)["']\s*\)/);
      if (dynamicImport?.[1]) edges.push({ from: path, specifier: dynamicImport[1], kind: "dynamic-import", line: lineNumber });
      continue;
    }

    if (extension === ".py") {
      const fromImport = line.match(/^\s*from\s+([A-Za-z0-9_.]+)\s+import\b/);
      if (fromImport?.[1]) edges.push({ from: path, specifier: fromImport[1], kind: "python-import", line: lineNumber });
      const directImport = line.match(/^\s*import\s+([A-Za-z0-9_.]+)/);
      if (directImport?.[1]) edges.push({ from: path, specifier: directImport[1], kind: "python-import", line: lineNumber });
      continue;
    }

    if (extension === ".go") {
      const single = line.match(/^\s*import\s+(?:[A-Za-z0-9_.]+\s+)?"([^"]+)"/);
      if (single?.[1]) edges.push({ from: path, specifier: single[1], kind: "go-import", line: lineNumber });
      const grouped = line.match(/^\s*(?:[A-Za-z0-9_.]+\s+)?"([A-Za-z0-9_./-]+)"\s*$/);
      if (grouped?.[1]) edges.push({ from: path, specifier: grouped[1], kind: "go-import", line: lineNumber });
    }
  }

  return edges;
}

function namedNodeRouteHandler(line: string): string | undefined {
  const match = line.match(/\b(?:app|router|server)\.(?:get|post|put|patch|delete|options|head)\s*\(\s*(?:"[^"]*"|'[^']*'|`[^`]*`)\s*,\s*([A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*)*)\s*\)\s*;?\s*(?:\/\/.*)?$/i);
  const argumentsList = match?.[1];
  if (!argumentsList) return undefined;
  const names = argumentsList.split(",").map((value) => value.trim()).filter(Boolean);
  return names.at(-1);
}

function collectRoutes(path: string, content: string): RouteSignal[] {
  const routes: RouteSignal[] = [];
  const lines = content.split(/\r?\n/);

  for (let index = 0; index < lines.length && routes.length < MAX_SIGNALS_PER_FILE; index += 1) {
    const line = lines[index] ?? "";
    const lineNumber = index + 1;

    const express = line.match(/\b(?:app|router|server)\.(get|post|put|patch|delete|options|head|use)\s*\(\s*["'`]([^"'`]+)["'`]/i);
    if (express?.[1] && express[2]) {
      const handler = namedNodeRouteHandler(line);
      routes.push({
        path,
        line: lineNumber,
        method: express[1].toUpperCase(),
        route: express[2],
        frameworkHint: "Node HTTP router",
        ...(handler ? { handler } : {}),
      });
      continue;
    }

    const decorator = line.match(/@(Get|Post|Put|Patch|Delete|Options|Head)\s*\(\s*["'`]([^"'`]*)["'`]\s*\)/);
    if (decorator?.[1] && decorator[2] !== undefined) {
      routes.push({ path, line: lineNumber, method: decorator[1].toUpperCase(), route: decorator[2] || "/", frameworkHint: "Decorator router" });
      continue;
    }

    const pythonRoute = line.match(/@(?:app|router|blueprint)\.(get|post|put|patch|delete|route)\s*\(\s*["']([^"']+)["']/i);
    if (pythonRoute?.[1] && pythonRoute[2]) {
      routes.push({ path, line: lineNumber, method: pythonRoute[1].toUpperCase(), route: pythonRoute[2], frameworkHint: "Python web router" });
      continue;
    }

    const django = line.match(/\bpath\s*\(\s*["']([^"']+)["']/);
    if (django?.[1]) routes.push({ path, line: lineNumber, method: "ANY", route: django[1], frameworkHint: "Django URLConf" });
  }

  return routes;
}

function collectAuthSignals(path: string, content: string): AuthSignal[] {
  const output: AuthSignal[] = [];
  const lines = content.split(/\r?\n/);
  const patterns: Array<[AuthSignal["kind"], RegExp]> = [
    ["authentication", /\b(authenticate|authentication|requireAuth|isAuthenticated|passport\.authenticate|login_required)\b/i],
    ["authorization", /\b(authorize|authorization|permission|permissions|role|roles|isAdmin|accessControl|acl)\b/i],
    ["session", /\b(session|cookieSession|express-session|sessionMiddleware)\b/i],
    ["token", /\b(jwt|bearer|access[_-]?token|id[_-]?token|verifyToken|decodeToken)\b/i],
  ];

  for (let index = 0; index < lines.length && output.length < MAX_SIGNALS_PER_FILE; index += 1) {
    const line = lines[index] ?? "";
    for (const [kind, pattern] of patterns) {
      if (!pattern.test(line)) continue;
      output.push({ path, line: index + 1, kind, evidence: sourceLine(lines, index) });
      break;
    }
  }
  return output;
}

function collectSinkSignals(path: string, content: string): SinkSignal[] {
  const output: SinkSignal[] = [];
  const lines = content.split(/\r?\n/);
  const patterns: Array<[SinkSignal["kind"], RegExp]> = [
    ["process", /\b(child_process|execFile|execSync|spawnSync|spawn\s*\(|exec\s*\(|subprocess\.|os\.system\s*\()/i],
    ["filesystem", /\b(writeFile|writeFileSync|appendFile|appendFileSync|unlink|rmSync|rename|createWriteStream|shutil\.|os\.remove\s*\()/i],
    ["database", /\b(query|execute|executemany|raw|rawQuery|createQueryRunner)\s*\(/i],
    ["network", /\b(fetch|axios\.|http\.request|https\.request|requests\.(get|post|put|patch|delete)|urllib\.)/i],
  ];

  for (let index = 0; index < lines.length && output.length < MAX_SIGNALS_PER_FILE; index += 1) {
    const line = lines[index] ?? "";
    for (const [kind, pattern] of patterns) {
      if (!pattern.test(line)) continue;
      output.push({ path, line: index + 1, kind, evidence: sourceLine(lines, index) });
      break;
    }
  }
  return output;
}

export async function buildRepositoryIndex(rootPath: string, files: readonly IndexFileInput[]): Promise<RepositoryIndex> {
  const root = resolve(rootPath);
  const moduleEdges: ModuleEdge[] = [];
  const routes: RouteSignal[] = [];
  const authSignals: AuthSignal[] = [];
  const sinks: SinkSignal[] = [];
  let indexedFileCount = 0;

  for (const file of files) {
    if (indexedFileCount >= MAX_INDEX_FILES) break;
    if (file.size > MAX_INDEX_FILE_BYTES || !analyzableExtensions.has(extname(file.path).toLowerCase())) continue;
    const absolute = resolve(root, file.path);
    const content = await readFile(absolute, "utf8").catch(() => undefined);
    if (content === undefined || content.includes("\u0000")) continue;

    indexedFileCount += 1;
    moduleEdges.push(...collectModuleEdges(file.path, content));
    routes.push(...collectRoutes(file.path, content));
    authSignals.push(...collectAuthSignals(file.path, content));
    sinks.push(...collectSinkSignals(file.path, content));
  }

  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    indexedFileCount,
    moduleEdges,
    routes,
    authSignals,
    sinks,
  };
}

export function packageNameFromPurl(purl: string | undefined): string | undefined {
  if (!purl?.startsWith("pkg:")) return undefined;
  const slash = purl.indexOf("/");
  if (slash < 0) return undefined;
  let value = purl.slice(slash + 1);
  const query = value.search(/[?#]/);
  if (query >= 0) value = value.slice(0, query);
  const version = value.lastIndexOf("@");
  if (version > 0) value = value.slice(0, version);
  try {
    value = decodeURIComponent(value);
  } catch {
    // Keep the raw package path when malformed percent encoding is present.
  }
  return value || undefined;
}

function moduleMatchesPackage(edge: ModuleEdge, packageName: string): boolean {
  const specifier = edge.specifier.toLowerCase();
  const normalized = packageName.toLowerCase();
  const pythonNormalized = normalized.replaceAll("-", "_");
  if (specifier === normalized || specifier.startsWith(`${normalized}/`)) return true;
  if (specifier === pythonNormalized || specifier.startsWith(`${pythonNormalized}.`)) return true;
  return false;
}

export function findDependencyUsage(index: RepositoryIndex, packageName: string, maxEvidence = 10): DependencyUsage {
  const evidence = index.moduleEdges
    .filter((edge) => moduleMatchesPackage(edge, packageName))
    .slice(0, Math.max(1, maxEvidence));
  return {
    packageName,
    status: evidence.length > 0 ? "observed-import" : "unknown",
    evidence,
  };
}

function normalizeIndexPath(value: string): string {
  return value.replaceAll("\\", "/").replace(/^\.\//, "").replace(/^\//, "").toLowerCase();
}

function distanceFrom(line: number | undefined, signalLine: number): number {
  return line === undefined ? 0 : Math.abs(signalLine - line);
}

export function findingRepositoryContext(
  index: RepositoryIndex,
  path: string,
  line?: number,
  radius = 40,
  maxPerKind = 5,
): FindingRepositoryContext {
  const normalizedPath = normalizeIndexPath(path);
  const boundedRadius = Math.max(0, radius);
  const limit = Math.max(1, maxPerKind);
  const sameFile = (signalPath: string): boolean => normalizeIndexPath(signalPath) === normalizedPath;
  const nearby = (signalLine: number): boolean => line === undefined || distanceFrom(line, signalLine) <= boundedRadius;

  const nearbyRoutes = index.routes
    .filter((signal) => sameFile(signal.path) && nearby(signal.line))
    .map((signal): NearbyRouteSignal => ({
      line: signal.line,
      distance: distanceFrom(line, signal.line),
      method: signal.method,
      route: signal.route,
      ...(signal.frameworkHint ? { frameworkHint: signal.frameworkHint } : {}),
    }))
    .sort((a, b) => a.distance - b.distance || a.line - b.line)
    .slice(0, limit);

  const nearbyAuthSignals = index.authSignals
    .filter((signal) => sameFile(signal.path) && nearby(signal.line))
    .map((signal): NearbySecuritySignal => ({
      line: signal.line,
      distance: distanceFrom(line, signal.line),
      kind: signal.kind,
    }))
    .sort((a, b) => a.distance - b.distance || a.line - b.line)
    .slice(0, limit);

  const nearbySinks = index.sinks
    .filter((signal) => sameFile(signal.path) && nearby(signal.line))
    .map((signal): NearbySecuritySignal => ({
      line: signal.line,
      distance: distanceFrom(line, signal.line),
      kind: signal.kind,
    }))
    .sort((a, b) => a.distance - b.distance || a.line - b.line)
    .slice(0, limit);

  const context: FindingRepositoryContext = {
    path,
    radius: boundedRadius,
    nearbyRoutes,
    nearbyAuthSignals,
    nearbySinks,
    interpretation: "proximity-signals-only",
  };
  if (line !== undefined) context.line = line;
  return context;
}

export function routeSecurityContext(index: RepositoryIndex, route: RouteSignal, radius = 30): RouteSecurityContext {
  const nearby = (line: number): boolean => Math.abs(line - route.line) <= Math.max(0, radius);
  return {
    route,
    nearbyAuthSignals: index.authSignals.filter((signal) => signal.path === route.path && nearby(signal.line)),
    nearbySinks: index.sinks.filter((signal) => signal.path === route.path && nearby(signal.line)),
  };
}

export async function writeRepositoryIndex(path: string, index: RepositoryIndex): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(index, null, 2)}\n`, "utf8");
}

export function isRepositoryIndex(value: unknown): value is RepositoryIndex {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return record.schemaVersion === 1 && Array.isArray(record.moduleEdges) && Array.isArray(record.routes) && Array.isArray(record.authSignals) && Array.isArray(record.sinks);
}

export async function readRepositoryIndex(path: string): Promise<RepositoryIndex> {
  const parsed = JSON.parse(await readFile(path, "utf8")) as unknown;
  if (!isRepositoryIndex(parsed)) throw new Error(`Not a supported SynSec repository index: ${path}`);
  return parsed;
}
