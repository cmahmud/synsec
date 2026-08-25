import { lstat, readFile } from "node:fs/promises";
import { extname, isAbsolute, relative, resolve, sep } from "node:path";
import type { IndexFileInput, RouteSignal } from "./analysis.js";
import { findCallNeighborhood, type CallGraph, type CallGraphNode } from "./call-graph.js";
import type { RouteEntrypoint } from "./route-entrypoints.js";

const MAX_SOURCE_BYTES = 512_000;
const DEFAULT_MAX_DECORATOR_DISTANCE = 8;
const MAX_DECORATOR_DISTANCE = 20;
const DEFAULT_MAX_ROUTES = 2_000;
const MAX_ROUTES = 10_000;

const HTTP_DECORATORS = new Map([
  ["Get", "GET"],
  ["Post", "POST"],
  ["Put", "PUT"],
  ["Patch", "PATCH"],
  ["Delete", "DELETE"],
  ["Options", "OPTIONS"],
  ["Head", "HEAD"],
]);

interface ClassSpan {
  path: string;
  name: string;
  line: number;
  endLine: number;
  prefix: string;
  controllerDecoratorLine: number;
  controllerGuards: GuardAttachment[];
}

interface MethodSpan {
  name: string;
  line: number;
  endLine: number;
}

interface GuardAttachment {
  name: string;
  line: number;
  scope: "controller" | "method";
}

export interface NestJsGuardContext {
  route: RouteSignal;
  controller: {
    path: string;
    name: string;
    line: number;
  };
  handler: {
    name: string;
    line: number;
  };
  guards: GuardAttachment[];
  /** Decorator attachment is structural evidence only; it is not proof that a guard executes or authorizes a request. */
  interpretation: "structural-nestjs-guard-attachment-not-runtime-protection";
}

export interface NestJsControllerCompositionResult {
  entrypoints: RouteEntrypoint[];
  guardContexts: NestJsGuardContext[];
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

function braceDelta(line: string): number {
  let delta = 0;
  let quote: "'" | '"' | "`" | undefined;
  let escaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    const next = line[index + 1];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quote) {
      if (char === "\\") escaped = true;
      else if (char === quote) quote = undefined;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") {
      quote = char;
      continue;
    }
    if (char === "/" && next === "/") break;
    if (char === "{") delta += 1;
    else if (char === "}") delta -= 1;
  }
  return delta;
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

function hasUnshadowedNestImport(content: string, symbol: string, useLine: number): boolean {
  const lines = content.split(/\r?\n/);
  const imports: number[] = [];
  for (let index = 0; index < Math.min(lines.length, useLine - 1); index += 1) {
    const match = (lines[index] ?? "").match(/^\s*import\s*\{([^}]+)\}\s*from\s*["']@nestjs\/common["']\s*;?\s*$/);
    if (!match?.[1]) continue;
    const parts = match[1].split(",").map((part) => part.trim());
    if (parts.some((part) => part === symbol)) imports.push(index + 1);
    if (parts.some((part) => new RegExp(`^${escapeIdentifier(symbol)}\\s+as\\s+`).test(part))) return false;
  }
  if (imports.length !== 1) return false;
  const importLine = imports[0];
  if (!importLine) return false;
  const escaped = escapeIdentifier(symbol);
  const declaration = new RegExp(`^\\s*(?:class|function|const|let|var)\\s+${escaped}\\b`);
  const assignment = new RegExp(`^\\s*${escaped}\\s*=(?!=)`);
  for (let index = importLine; index < useLine - 1; index += 1) {
    const line = lines[index] ?? "";
    if (declaration.test(line) || assignment.test(line)) return false;
  }
  return true;
}

function decoratorBlock(lines: readonly string[], declarationLine: number, maxDistance: number): Array<{ line: number; text: string }> {
  const output: Array<{ line: number; text: string }> = [];
  let cursor = declarationLine - 2;
  while (cursor >= 0 && declarationLine - (cursor + 1) <= maxDistance) {
    const text = (lines[cursor] ?? "").trim();
    if (!text) {
      cursor -= 1;
      continue;
    }
    if (!text.startsWith("@")) break;
    output.push({ line: cursor + 1, text });
    cursor -= 1;
  }
  return output.reverse();
}

function parseLiteralDecorator(text: string, name: string): string | undefined {
  const escaped = escapeIdentifier(name);
  const empty = new RegExp(`^@${escaped}\\(\\s*\\)\\s*;?$`).exec(text);
  if (empty) return "";
  const literal = new RegExp(`^@${escaped}\\(\\s*(["'])([^"']*)\\1\\s*\\)\\s*;?$`).exec(text);
  return literal?.[2] === undefined ? undefined : normalizeRoute(literal[2]);
}

function parseGuards(text: string): string[] | undefined {
  const match = text.match(/^@UseGuards\(\s*([^)]*?)\s*\)\s*;?$/);
  if (!match?.[1]) return undefined;
  const names = match[1].split(",").map((part) => part.trim());
  if (names.length === 0 || names.some((name) => !/^[A-Za-z_$][\w$]*$/.test(name))) return undefined;
  return names;
}

function classSpan(lines: readonly string[], startIndex: number): { name: string; endLine: number } | undefined {
  const line = lines[startIndex] ?? "";
  const match = line.match(/^\s*(?:export\s+)?(?:default\s+)?class\s+([A-Za-z_$][\w$]*)(?:\s+extends\s+[^\{]+)?\s*\{/);
  const name = match?.[1];
  if (!name) return undefined;
  let depth = braceDelta(line);
  if (depth <= 0) return undefined;
  for (let cursor = startIndex + 1; cursor < lines.length; cursor += 1) {
    depth += braceDelta(lines[cursor] ?? "");
    if (depth <= 0) return { name, endLine: cursor + 1 };
  }
  return undefined;
}

function classMethods(lines: readonly string[], controller: ClassSpan): MethodSpan[] {
  const output: MethodSpan[] = [];
  let depth = 1;
  for (let index = controller.line; index < controller.endLine - 1; index += 1) {
    const line = lines[index] ?? "";
    if (depth === 1) {
      const match = line.match(/^\s*(?:(?:public|private|protected|static|readonly|override|async)\s+)*([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*(?::[^\{]+)?\s*\{/);
      const name = match?.[1];
      if (name && name !== "constructor") {
        let methodDepth = braceDelta(line);
        if (methodDepth > 0) {
          let endLine = index + 1;
          for (let cursor = index + 1; cursor < controller.endLine; cursor += 1) {
            methodDepth += braceDelta(lines[cursor] ?? "");
            endLine = cursor + 1;
            if (methodDepth <= 0) break;
          }
          output.push({ name, line: index + 1, endLine });
        }
      }
    }
    depth += braceDelta(line);
  }
  return output;
}

function routeKey(entrypoint: RouteEntrypoint): string {
  return [normalizePath(entrypoint.route.path), entrypoint.route.line, entrypoint.route.method, entrypoint.route.route, entrypoint.handler?.id ?? ""].join("\0");
}

/**
 * Resolve explicit NestJS controller + HTTP-method decorators into bounded structural route entrypoints.
 *
 * Only unaliased one-line named imports from `@nestjs/common`, literal `@Controller()` prefixes,
 * literal/empty HTTP decorators, and immediate class methods are accepted. `@UseGuards()` evidence is
 * retained only for plain identifier arguments. Dynamic decorator arguments, decorator aliases,
 * factories such as `AuthGuard("jwt")`, shadowed decorator bindings, malformed class boundaries, and
 * unsupported syntax fail closed. Synthetic class-method nodes are added only to the caller-owned
 * lexical call graph so exact sinks inside the resolved method can participate in existing route/sink
 * correlation. No claim is made that NestJS instantiates the controller, executes a guard, exposes the
 * route at runtime, or makes a finding exploitable.
 */
export async function composeNestJsControllerEntrypoints(
  rootPath: string,
  files: readonly IndexFileInput[],
  graph: CallGraph,
  entrypoints: readonly RouteEntrypoint[],
  options: { maxDecoratorDistance?: number; maxRoutes?: number; maxCallDepth?: number; maxCallNodes?: number } = {},
): Promise<NestJsControllerCompositionResult> {
  const maxDecoratorDistance = boundedInteger(options.maxDecoratorDistance, DEFAULT_MAX_DECORATOR_DISTANCE, MAX_DECORATOR_DISTANCE, "NestJS maxDecoratorDistance");
  const maxRoutes = boundedInteger(options.maxRoutes, DEFAULT_MAX_ROUTES, MAX_ROUTES, "NestJS maxRoutes");
  const maxCallDepth = Math.max(0, Math.min(20, options.maxCallDepth ?? 3));
  const maxCallNodes = Math.max(1, Math.min(1_000, options.maxCallNodes ?? 100));
  const output = [...entrypoints];
  const existing = new Set(output.map(routeKey));
  const guardContexts: NestJsGuardContext[] = [];
  let produced = 0;

  for (const file of files) {
    if (produced >= maxRoutes) break;
    const content = await safeReadSource(rootPath, file);
    if (content === undefined) continue;
    const path = normalizePath(file.path);
    const lines = content.split(/\r?\n/);
    const controllers: ClassSpan[] = [];

    for (let index = 0; index < lines.length; index += 1) {
      const span = classSpan(lines, index);
      if (!span) continue;
      const declarationLine = index + 1;
      const decorators = decoratorBlock(lines, declarationLine, maxDecoratorDistance);
      const controllerDecorators = decorators.flatMap((decorator) => {
        const prefix = parseLiteralDecorator(decorator.text, "Controller");
        return prefix === undefined ? [] : [{ ...decorator, prefix }];
      });
      if (controllerDecorators.length !== 1) continue;
      const controllerDecorator = controllerDecorators[0];
      if (!controllerDecorator || !hasUnshadowedNestImport(content, "Controller", controllerDecorator.line)) continue;

      const controllerGuards: GuardAttachment[] = [];
      let invalidGuardDecorator = false;
      for (const decorator of decorators.filter((candidate) => candidate.text.startsWith("@UseGuards"))) {
        if (!hasUnshadowedNestImport(content, "UseGuards", decorator.line)) {
          invalidGuardDecorator = true;
          break;
        }
        const guards = parseGuards(decorator.text);
        if (!guards) {
          invalidGuardDecorator = true;
          break;
        }
        controllerGuards.push(...guards.map((name) => ({ name, line: decorator.line, scope: "controller" as const })));
      }
      if (invalidGuardDecorator) continue;
      controllers.push({
        path,
        name: span.name,
        line: declarationLine,
        endLine: span.endLine,
        prefix: controllerDecorator.prefix,
        controllerDecoratorLine: controllerDecorator.line,
        controllerGuards,
      });
      index = span.endLine - 1;
    }

    for (const controller of controllers) {
      for (const method of classMethods(lines, controller)) {
        if (produced >= maxRoutes) break;
        const decorators = decoratorBlock(lines, method.line, maxDecoratorDistance);
        const routeDecorators: Array<{ line: number; method: string; route: string; symbol: string }> = [];
        for (const decorator of decorators) {
          for (const [symbol, httpMethod] of HTTP_DECORATORS) {
            const route = parseLiteralDecorator(decorator.text, symbol);
            if (route === undefined) continue;
            if (!hasUnshadowedNestImport(content, symbol, decorator.line)) continue;
            routeDecorators.push({ line: decorator.line, method: httpMethod, route, symbol });
          }
        }
        if (routeDecorators.length !== 1) continue;
        const routeDecorator = routeDecorators[0];
        if (!routeDecorator) continue;

        const methodGuards: GuardAttachment[] = [];
        let invalidGuardDecorator = false;
        for (const decorator of decorators.filter((candidate) => candidate.text.startsWith("@UseGuards"))) {
          if (!hasUnshadowedNestImport(content, "UseGuards", decorator.line)) {
            invalidGuardDecorator = true;
            break;
          }
          const guards = parseGuards(decorator.text);
          if (!guards) {
            invalidGuardDecorator = true;
            break;
          }
          methodGuards.push(...guards.map((name) => ({ name, line: decorator.line, scope: "method" as const })));
        }
        if (invalidGuardDecorator) continue;

        const handlerId = `${path}:${controller.name}.${method.name}:${method.line}`;
        let handler = graph.nodes.find((node) => node.id === handlerId);
        if (!handler) {
          handler = {
            id: handlerId,
            path,
            name: method.name,
            line: method.line,
            endLine: method.endLine,
            kind: "function",
          } satisfies CallGraphNode;
          graph.nodes.push(handler);
        }
        const route: RouteSignal = {
          path,
          line: routeDecorator.line,
          method: routeDecorator.method,
          route: composeRoute(controller.prefix, routeDecorator.route),
          frameworkHint: "NestJS controller",
          handler: method.name,
        };
        const entrypoint: RouteEntrypoint = {
          route,
          resolution: "decorated-function",
          handler,
          calls: findCallNeighborhood(graph, handler.id, maxCallDepth, maxCallNodes),
          interpretation: "structural-route-call-evidence-only",
        };
        const key = routeKey(entrypoint);
        if (existing.has(key)) continue;
        existing.add(key);
        output.push(entrypoint);
        produced += 1;

        const guards = [...controller.controllerGuards, ...methodGuards];
        if (guards.length > 0) {
          guardContexts.push({
            route,
            controller: { path, name: controller.name, line: controller.line },
            handler: { name: method.name, line: method.line },
            guards,
            interpretation: "structural-nestjs-guard-attachment-not-runtime-protection",
          });
        }
      }
    }
  }

  return { entrypoints: output, guardContexts };
}
