import { lstat, readFile } from "node:fs/promises";
import { extname, isAbsolute, relative, resolve, sep } from "node:path";
import type { IndexFileInput } from "./analysis.js";
import { buildCallGraph, findCallNeighborhood, type CallGraph, type CallGraphNode } from "./call-graph.js";
import type { ModuleGraph, ResolvedModuleEdge } from "./module-graph.js";
import type { RouteEntrypoint } from "./route-entrypoints.js";

const MAX_SOURCE_BYTES = 512_000;
const DEFAULT_MAX_REGISTER_DEPTH = 8;
const MAX_REGISTER_DEPTH = 32;
const DEFAULT_MAX_COMPOSED_ROUTES = 2_000;
const MAX_COMPOSED_ROUTES = 10_000;
const DEFAULT_MAX_DECLARATION_DISTANCE = 5;

interface FlaskAppNode {
  path: string;
  name: string;
  declarationLine: number;
}

interface FlaskBlueprintNode {
  path: string;
  name: string;
  prefix: string;
  declarationLine: number;
}

interface ImportedBlueprintBinding {
  localName: string;
  importedName: string;
  edge: ResolvedModuleEdge;
}

interface BlueprintRegistrationEdge {
  app?: FlaskAppNode;
  parent?: FlaskBlueprintNode;
  child: FlaskBlueprintNode;
  prefix: string;
}

interface BlueprintRoute {
  blueprint: FlaskBlueprintNode;
  entrypoint: RouteEntrypoint;
}

export interface FlaskComposedRouteEntrypoint extends RouteEntrypoint {
  composition: {
    rootPath: string;
    registerDepth: number;
    blueprintPath: string;
    blueprintName: string;
    prefixes: string[];
  };
  /** Static blueprint composition is not proof that Flask imports, registers, or serves the route. */
  compositionInterpretation: "structural-flask-blueprint-composition-not-runtime-reachability";
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

function explicitFlaskImport(content: string, symbol: "Flask" | "Blueprint", beforeLine: number): boolean {
  const lines = content.split(/\r?\n/).slice(0, Math.max(0, beforeLine - 1));
  let imported = false;
  for (const line of lines) {
    const match = line.match(/^\s*from\s+flask\s+import\s+(.+?)\s*(?:#.*)?$/);
    if (!match?.[1] || match[1].includes("(")) continue;
    for (const raw of match[1].split(",")) {
      if (raw.trim() === symbol) imported = true;
    }
  }
  if (!imported) return false;
  const escaped = escapeIdentifier(symbol);
  const declaration = new RegExp(`^\\s*(?:async\\s+def|def|class)\\s+${escaped}\\b`);
  const assignment = new RegExp(`^\\s*${escaped}\\s*(?::[^=]+)?=(?!=)`);
  return !lines.some((line) => declaration.test(line) || assignment.test(line));
}

function parseAppDeclaration(line: string): string | undefined {
  const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*Flask\s*\(\s*__name__\s*\)\s*(?:#.*)?$/);
  return match?.[1];
}

function parseBlueprintDeclaration(line: string): { name: string; prefix: string } | undefined {
  const match = line.match(
    /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*Blueprint\s*\(\s*(["'])([^"']+)\2\s*,\s*__name__(?:\s*,\s*url_prefix\s*=\s*(["'])([^"']*)\4)?\s*\)\s*(?:#.*)?$/,
  );
  const name = match?.[1];
  if (!name) return undefined;
  return { name, prefix: normalizePrefix(match?.[5] ?? "") };
}

function parseNamedImport(line: string, edge: ResolvedModuleEdge): ImportedBlueprintBinding[] {
  const match = line.match(/^\s*from\s+([A-Za-z0-9_.]+)\s+import\s+(.+?)\s*(?:#.*)?$/);
  if (!match?.[1] || match[1] !== edge.specifier || !match[2] || match[2].includes("(")) return [];
  const output: ImportedBlueprintBinding[] = [];
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

function bindingShadowedBeforeUse(content: string, binding: ImportedBlueprintBinding, useLine: number): boolean {
  if (useLine <= binding.edge.line) return true;
  const escaped = escapeIdentifier(binding.localName);
  const lines = content.split(/\r?\n/).slice(binding.edge.line, useLine - 1);
  const declaration = new RegExp(`^\\s*(?:async\\s+def|def|class)\\s+${escaped}\\b`);
  const assignment = new RegExp(`^\\s*${escaped}\\s*(?::[^=]+)?=(?!=)`);
  const importBinding = new RegExp(`^\\s*(?:from\\s+[^\\s]+\\s+import|import)\\b.*\\b${escaped}\\b`);
  return lines.some((line) => declaration.test(line) || assignment.test(line) || importBinding.test(line));
}

function parseRegistration(line: string): { receiver: string; childName: string; prefix: string } | undefined {
  const match = line.match(
    /^\s*([A-Za-z_][A-Za-z0-9_]*)\.register_blueprint\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)(?:\s*,\s*url_prefix\s*=\s*(["'])([^"']*)\3)?\s*\)\s*(?:#.*)?$/,
  );
  const receiver = match?.[1];
  const childName = match?.[2];
  if (!receiver || !childName) return undefined;
  return { receiver, childName, prefix: normalizePrefix(match?.[4] ?? "") };
}

function parseBlueprintRoute(line: string): { blueprintName: string; method: string; route: string } | undefined {
  const match = line.match(
    /^\s*@([A-Za-z_][A-Za-z0-9_]*)\.(get|post|put|patch|delete|options|head|route)\s*\(\s*(["'])([^"']+)\3(?:\s*,[^)]*)?\)\s*(?:#.*)?$/i,
  );
  const blueprintName = match?.[1];
  const method = match?.[2];
  const route = match?.[4];
  if (!blueprintName || !method || route === undefined) return undefined;
  return { blueprintName, method: method.toLowerCase() === "route" ? "ANY" : method.toUpperCase(), route };
}

function blueprintKey(path: string, name: string): string {
  return `${normalizePath(path)}\0${name}`;
}

function appKey(path: string, name: string): string {
  return `${normalizePath(path)}\0${name}`;
}

function routeKey(entrypoint: RouteEntrypoint): string {
  const handler = entrypoint.handler;
  return [normalizePath(entrypoint.route.path), entrypoint.route.line, entrypoint.route.method, entrypoint.route.route, handler?.id ?? ""].join("\0");
}

function nearestPythonHandler(
  graph: CallGraph,
  path: string,
  routeLine: number,
  maxDeclarationDistance: number,
): CallGraphNode | undefined {
  const candidates = graph.nodes
    .filter((node) => (
      node.kind === "python-function"
      && normalizePath(node.path) === normalizePath(path)
      && node.line > routeLine
      && node.line - routeLine <= maxDeclarationDistance
    ))
    .sort((left, right) => left.line - right.line || left.name.localeCompare(right.name));
  const first = candidates[0];
  if (!first) return undefined;
  const nearest = candidates.filter((candidate) => candidate.line === first.line);
  return nearest.length === 1 ? first : undefined;
}

/**
 * Compose explicit Flask Blueprint url prefixes across bounded register_blueprint() relationships.
 *
 * This accepts only one-line, unaliased `from flask import Flask, Blueprint` imports, exact
 * `app = Flask(__name__)` roots, literal `Blueprint("name", __name__[, url_prefix="..."])`
 * declarations, and exact `register_blueprint(name[, url_prefix="..."])` calls. Imported blueprint
 * bindings require one repository-local named Python import resolving to one matching declaration and
 * must remain unshadowed before use. Route decorators are independently revalidated as exact named
 * blueprint decorators and linked only to the unique nearest following Python function. Dynamic
 * prefixes, factories, dotted blueprint references, imported Flask app roots, wildcard/parenthesized
 * imports, ambiguous declarations, use-before-definition, cycles, and unresolved modules fail closed.
 * Returned route identities are bounded structural evidence, not proof that Flask imports, registers,
 * or serves a blueprint at runtime.
 */
export async function composeFlaskBlueprintEntrypoints(
  rootPath: string,
  files: readonly IndexFileInput[],
  moduleGraph: ModuleGraph,
  entrypoints: readonly RouteEntrypoint[],
  options: {
    maxRegisterDepth?: number;
    maxComposedRoutes?: number;
    maxDeclarationDistance?: number;
    maxCallDepth?: number;
    maxCallNodes?: number;
  } = {},
): Promise<RouteEntrypoint[]> {
  const maxRegisterDepth = boundedInteger(options.maxRegisterDepth, DEFAULT_MAX_REGISTER_DEPTH, MAX_REGISTER_DEPTH, "Flask blueprint maxRegisterDepth");
  const maxComposedRoutes = boundedInteger(options.maxComposedRoutes, DEFAULT_MAX_COMPOSED_ROUTES, MAX_COMPOSED_ROUTES, "Flask blueprint maxComposedRoutes");
  const maxDeclarationDistance = boundedInteger(options.maxDeclarationDistance, DEFAULT_MAX_DECLARATION_DISTANCE, 20, "Flask blueprint maxDeclarationDistance");
  const maxCallDepth = Math.max(0, Math.min(20, options.maxCallDepth ?? 3));
  const maxCallNodes = Math.max(1, Math.min(1_000, options.maxCallNodes ?? 100));
  const graph = await buildCallGraph(rootPath, files);
  const sourceByPath = new Map<string, string>();
  for (const file of files.filter((candidate) => extname(candidate.path).toLowerCase() === ".py")) {
    const source = await safeReadSource(rootPath, file);
    if (source !== undefined) sourceByPath.set(normalizePath(file.path), source);
  }

  const apps = new Map<string, FlaskAppNode>();
  const blueprints = new Map<string, FlaskBlueprintNode>();
  const ambiguousBlueprints = new Set<string>();
  for (const [path, content] of sourceByPath) {
    const lines = content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index] ?? "";
      const appName = parseAppDeclaration(line);
      if (appName && explicitFlaskImport(content, "Flask", index + 1)) {
        const key = appKey(path, appName);
        if (!apps.has(key)) apps.set(key, { path, name: appName, declarationLine: index + 1 });
      }
      const parsedBlueprint = parseBlueprintDeclaration(line);
      if (!parsedBlueprint || !explicitFlaskImport(content, "Blueprint", index + 1)) continue;
      const key = blueprintKey(path, parsedBlueprint.name);
      if (blueprints.has(key)) {
        blueprints.delete(key);
        ambiguousBlueprints.add(key);
        continue;
      }
      if (!ambiguousBlueprints.has(key)) {
        blueprints.set(key, {
          path,
          name: parsedBlueprint.name,
          prefix: parsedBlueprint.prefix,
          declarationLine: index + 1,
        });
      }
    }
  }

  const importBindingsByPath = new Map<string, ImportedBlueprintBinding[]>();
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

  function resolveBlueprint(path: string, localName: string, useLine: number): FlaskBlueprintNode | undefined {
    const normalized = normalizePath(path);
    const sameFile = blueprints.get(blueprintKey(normalized, localName));
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
    return binding?.edge.target ? blueprints.get(blueprintKey(binding.edge.target, binding.importedName)) : undefined;
  }

  const registrations: BlueprintRegistrationEdge[] = [];
  for (const [path, content] of sourceByPath) {
    const lines = content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const parsed = parseRegistration(lines[index] ?? "");
      if (!parsed) continue;
      const line = index + 1;
      const child = resolveBlueprint(path, parsed.childName, line);
      if (!child) continue;
      const app = apps.get(appKey(path, parsed.receiver));
      if (app && app.declarationLine < line) {
        registrations.push({ app, child, prefix: parsed.prefix });
        continue;
      }
      const parent = resolveBlueprint(path, parsed.receiver, line);
      if (parent) registrations.push({ parent, child, prefix: parsed.prefix });
    }
  }

  const routesByBlueprint = new Map<string, BlueprintRoute[]>();
  for (const [path, content] of sourceByPath) {
    const lines = content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const parsed = parseBlueprintRoute(lines[index] ?? "");
      if (!parsed) continue;
      const routeLine = index + 1;
      const blueprint = blueprints.get(blueprintKey(path, parsed.blueprintName));
      if (!blueprint || blueprint.declarationLine >= routeLine) continue;
      const handler = nearestPythonHandler(graph, path, routeLine, maxDeclarationDistance);
      if (!handler) continue;
      const entrypoint: RouteEntrypoint = {
        route: {
          path,
          line: routeLine,
          method: parsed.method,
          route: parsed.route,
          frameworkHint: "Flask blueprint",
        },
        resolution: "decorated-function",
        handler,
        calls: findCallNeighborhood(graph, handler.id, maxCallDepth, maxCallNodes),
        interpretation: "structural-route-call-evidence-only",
      };
      const key = blueprintKey(blueprint.path, blueprint.name);
      routesByBlueprint.set(key, [...(routesByBlueprint.get(key) ?? []), { blueprint, entrypoint }]);
    }
  }

  const childEdges = new Map<string, BlueprintRegistrationEdge[]>();
  for (const edge of registrations) {
    if (!edge.parent) continue;
    const key = blueprintKey(edge.parent.path, edge.parent.name);
    childEdges.set(key, [...(childEdges.get(key) ?? []), edge]);
  }

  const composed: RouteEntrypoint[] = [];
  const composedKeys = new Set<string>();

  function appendRoutes(
    blueprint: FlaskBlueprintNode,
    prefixes: string[],
    depth: number,
    rootPathValue: string,
    seen: ReadonlySet<string>,
  ): void {
    if (composed.length >= maxComposedRoutes || depth > maxRegisterDepth) return;
    const key = blueprintKey(blueprint.path, blueprint.name);
    if (seen.has(key)) return;
    const nextSeen = new Set(seen);
    nextSeen.add(key);
    const effectivePrefixes = [...prefixes, blueprint.prefix].filter(Boolean);

    for (const route of routesByBlueprint.get(key) ?? []) {
      if (composed.length >= maxComposedRoutes) return;
      const candidate: FlaskComposedRouteEntrypoint = {
        ...route.entrypoint,
        route: {
          ...route.entrypoint.route,
          route: composeRoute([...effectivePrefixes, route.entrypoint.route.route]),
          frameworkHint: "Flask composed blueprint",
        },
        composition: {
          rootPath: rootPathValue,
          registerDepth: depth,
          blueprintPath: blueprint.path,
          blueprintName: blueprint.name,
          prefixes: effectivePrefixes,
        },
        compositionInterpretation: "structural-flask-blueprint-composition-not-runtime-reachability",
      };
      const candidateKey = routeKey(candidate);
      if (!composedKeys.has(candidateKey)) {
        composedKeys.add(candidateKey);
        composed.push(candidate);
      }
    }

    for (const edge of childEdges.get(key) ?? []) {
      appendRoutes(edge.child, [...effectivePrefixes, edge.prefix].filter(Boolean), depth + 1, rootPathValue, nextSeen);
    }
  }

  for (const root of registrations.filter((edge) => edge.app !== undefined)) {
    if (composed.length >= maxComposedRoutes) break;
    appendRoutes(root.child, root.prefix ? [root.prefix] : [], 1, root.app?.path ?? root.child.path, new Set());
  }

  const existingKeys = new Set(entrypoints.map(routeKey));
  return [...entrypoints, ...composed.filter((entrypoint) => !existingKeys.has(routeKey(entrypoint)))];
}
