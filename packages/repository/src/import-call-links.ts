import { lstat, readFile } from "node:fs/promises";
import { extname, isAbsolute, relative, resolve, sep } from "node:path";
import type { IndexFileInput } from "./analysis.js";
import type { CallGraph } from "./call-graph.js";
import type { ModuleGraph } from "./module-graph.js";

export type ImportCallBindingKind =
  | "javascript-named-import"
  | "javascript-namespace-import"
  | "commonjs-destructured-require"
  | "python-from-import"
  | "python-module-import";

export interface ImportCallLink {
  from: string;
  line: number;
  callee: string;
  target: string;
  targetPath: string;
  importedName: string;
  bindingKind: ImportCallBindingKind;
  /**
   * This link exists only because an explicit import binding resolved to one
   * repository-local module and exactly one lexical function with that name.
   */
  evidence: "explicit-import-binding-to-unique-local-function";
}

export interface ImportCallLinkGraph {
  schemaVersion: 1;
  links: ImportCallLink[];
  linkedCallCount: number;
  /** Import/call syntax is structural review evidence, not runtime data flow. */
  interpretation: "cross-module-import-call-evidence-only";
}

interface ImportBinding {
  fromPath: string;
  line: number;
  targetPath: string;
  localName: string;
  importedName?: string;
  namespace: boolean;
  kind: ImportCallBindingKind;
}

const MAX_SOURCE_BYTES = 512_000;
const MAX_FILES = 5_000;
const MAX_BINDINGS_PER_FILE = 500;
const MAX_LINKS = 10_000;
const jsExtensions = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"]);

function normalizedPath(value: string): string {
  return value.replaceAll("\\", "/").replace(/^\.\//, "");
}

function insideRoot(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

async function readBoundedSource(root: string, file: IndexFileInput): Promise<string | undefined> {
  if (file.size > MAX_SOURCE_BYTES) return undefined;
  const normalized = normalizedPath(file.path);
  if (!normalized || normalized.startsWith("../") || isAbsolute(file.path)) return undefined;
  const absolute = resolve(root, normalized);
  if (!insideRoot(root, absolute)) return undefined;
  const info = await lstat(absolute).catch(() => undefined);
  if (!info?.isFile() || info.isSymbolicLink() || info.size > MAX_SOURCE_BYTES) return undefined;
  const content = await readFile(absolute, "utf8").catch(() => undefined);
  if (content === undefined || content.includes("\u0000")) return undefined;
  return content;
}

function resolvedTargetForLine(moduleGraph: ModuleGraph, fromPath: string, line: number): string | undefined {
  const candidates = moduleGraph.edges
    .filter((edge) => edge.target && normalizedPath(edge.from) === fromPath && edge.line === line)
    .map((edge) => edge.target as string);
  const unique = [...new Set(candidates)];
  return unique.length === 1 ? unique[0] : undefined;
}

function parseJsNamedList(value: string): Array<{ localName: string; importedName: string }> {
  const output: Array<{ localName: string; importedName: string }> = [];
  for (const rawPart of value.split(",")) {
    const part = rawPart.trim().replace(/^type\s+/, "");
    if (!part) continue;
    const match = part.match(/^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$/);
    if (!match?.[1]) continue;
    output.push({ importedName: match[1], localName: match[2] ?? match[1] });
  }
  return output;
}

function parseCommonJsNamedList(value: string): Array<{ localName: string; importedName: string }> {
  const output: Array<{ localName: string; importedName: string }> = [];
  for (const rawPart of value.split(",")) {
    const part = rawPart.trim();
    if (!part) continue;
    const match = part.match(/^([A-Za-z_$][\w$]*)(?:\s*:\s*([A-Za-z_$][\w$]*))?$/);
    if (!match?.[1]) continue;
    output.push({ importedName: match[1], localName: match[2] ?? match[1] });
  }
  return output;
}

function parsePythonNamedList(value: string): Array<{ localName: string; importedName: string }> {
  const output: Array<{ localName: string; importedName: string }> = [];
  for (const rawPart of value.replace(/^\(/, "").replace(/\)$/, "").split(",")) {
    const part = rawPart.trim();
    if (!part || part === "*") continue;
    const match = part.match(/^([A-Za-z_][A-Za-z0-9_]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?$/);
    if (!match?.[1]) continue;
    output.push({ importedName: match[1], localName: match[2] ?? match[1] });
  }
  return output;
}

function collectBindingsForLine(
  fromPath: string,
  lineNumber: number,
  line: string,
  extension: string,
  targetPath: string,
): ImportBinding[] {
  if (jsExtensions.has(extension)) {
    const namedImport = line.match(/^\s*import\s*{([^}]+)}\s*from\s*["'][^"']+["']/);
    if (namedImport?.[1]) {
      return parseJsNamedList(namedImport[1]).map((binding) => ({
        fromPath,
        line: lineNumber,
        targetPath,
        ...binding,
        namespace: false,
        kind: "javascript-named-import" as const,
      }));
    }

    const namespaceImport = line.match(/^\s*import\s*\*\s*as\s*([A-Za-z_$][\w$]*)\s*from\s*["'][^"']+["']/);
    if (namespaceImport?.[1]) {
      return [{
        fromPath,
        line: lineNumber,
        targetPath,
        localName: namespaceImport[1],
        namespace: true,
        kind: "javascript-namespace-import",
      }];
    }

    const destructuredRequire = line.match(/^\s*(?:const|let|var)\s*{([^}]+)}\s*=\s*require\s*\(\s*["'][^"']+["']\s*\)/);
    if (destructuredRequire?.[1]) {
      return parseCommonJsNamedList(destructuredRequire[1]).map((binding) => ({
        fromPath,
        line: lineNumber,
        targetPath,
        ...binding,
        namespace: false,
        kind: "commonjs-destructured-require" as const,
      }));
    }
    return [];
  }

  if (extension === ".py") {
    const fromImport = line.match(/^\s*from\s+[A-Za-z0-9_.]+\s+import\s+(.+?)\s*(?:#.*)?$/);
    if (fromImport?.[1]) {
      return parsePythonNamedList(fromImport[1]).map((binding) => ({
        fromPath,
        line: lineNumber,
        targetPath,
        ...binding,
        namespace: false,
        kind: "python-from-import" as const,
      }));
    }

    const moduleImport = line.match(/^\s*import\s+([A-Za-z0-9_.]+)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*(?:#.*)?$/);
    if (moduleImport?.[1]) {
      const localName = moduleImport[2] ?? moduleImport[1].split(".")[0];
      if (!localName) return [];
      return [{
        fromPath,
        line: lineNumber,
        targetPath,
        localName,
        namespace: true,
        kind: "python-module-import",
      }];
    }
  }

  return [];
}

async function collectImportBindings(
  root: string,
  files: readonly IndexFileInput[],
  moduleGraph: ModuleGraph,
): Promise<ImportBinding[]> {
  const bindings: ImportBinding[] = [];
  for (const file of files.slice(0, MAX_FILES)) {
    const extension = extname(file.path).toLowerCase();
    if (!jsExtensions.has(extension) && extension !== ".py") continue;
    const fromPath = normalizedPath(file.path);
    const content = await readBoundedSource(root, file);
    if (!content) continue;
    const lines = content.split(/\r?\n/);
    let fileBindingCount = 0;
    for (let index = 0; index < lines.length && fileBindingCount < MAX_BINDINGS_PER_FILE; index += 1) {
      const targetPath = resolvedTargetForLine(moduleGraph, fromPath, index + 1);
      if (!targetPath) continue;
      const parsed = collectBindingsForLine(fromPath, index + 1, lines[index] ?? "", extension, targetPath);
      for (const binding of parsed) {
        bindings.push(binding);
        fileBindingCount += 1;
        if (fileBindingCount >= MAX_BINDINGS_PER_FILE) break;
      }
    }
  }
  return bindings;
}

function bindingMatch(binding: ImportBinding, callee: string): string | undefined {
  if (binding.namespace) {
    const prefix = `${binding.localName}.`;
    if (!callee.startsWith(prefix)) return undefined;
    const member = callee.slice(prefix.length);
    return /^[A-Za-z_$][\w$]*$/.test(member) ? member : undefined;
  }
  return callee === binding.localName ? binding.importedName : undefined;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function callerShadowsBinding(
  source: string,
  callerLine: number,
  callLine: number,
  localName: string,
): boolean {
  if (!Number.isSafeInteger(callerLine) || !Number.isSafeInteger(callLine) || callerLine < 1 || callLine < callerLine) {
    return true;
  }
  const escaped = escapeRegExp(localName);
  const variableDeclaration = new RegExp(`\\b(?:const|let|var)\\s+${escaped}\\b`);
  const namedDeclaration = new RegExp(`\\b(?:class|function|def)\\s+${escaped}\\b`);
  const bindingDeclaration = new RegExp(`\\b(?:for|catch|except)\\b[^;\\n]*\\b${escaped}\\b`);
  const assignment = new RegExp(`^\\s*${escaped}\\s*=`);
  const parameter = new RegExp(`\\([^)]*\\b${escaped}\\b[^)]*\\)`);
  const lines = source.split(/\r?\n/);
  const start = Math.max(0, callerLine - 1);
  const end = Math.min(lines.length, callLine);

  for (let index = start; index < end; index += 1) {
    const line = lines[index] ?? "";
    if (variableDeclaration.test(line) || namedDeclaration.test(line) || bindingDeclaration.test(line) || assignment.test(line)) {
      return true;
    }
    if (index === start && parameter.test(line)) return true;
  }
  return false;
}

async function sourceForPath(
  root: string,
  path: string,
  cache: Map<string, string | undefined>,
): Promise<string | undefined> {
  const normalized = normalizedPath(path);
  if (cache.has(normalized)) return cache.get(normalized);
  const source = await readBoundedSource(root, { path: normalized, size: 0 });
  cache.set(normalized, source);
  return source;
}

export async function buildImportCallLinkGraph(
  rootPath: string,
  files: readonly IndexFileInput[],
  moduleGraph: ModuleGraph,
  callGraph: CallGraph,
): Promise<ImportCallLinkGraph> {
  const root = resolve(rootPath);
  const bindings = await collectImportBindings(root, files, moduleGraph);
  const nodeById = new Map(callGraph.nodes.map((node) => [node.id, node]));
  const functionsByPathAndName = new Map<string, string[]>();
  const sourceCache = new Map<string, string | undefined>();
  for (const node of callGraph.nodes) {
    const key = `${normalizedPath(node.path)}\u0000${node.name}`;
    const bucket = functionsByPathAndName.get(key) ?? [];
    bucket.push(node.id);
    functionsByPathAndName.set(key, bucket);
  }

  const links: ImportCallLink[] = [];
  for (const edge of callGraph.edges) {
    if (edge.target || links.length >= MAX_LINKS) continue;
    const caller = nodeById.get(edge.from);
    if (!caller) continue;
    const callerPath = normalizedPath(caller.path);
    const matches = bindings.flatMap((binding) => {
      if (binding.fromPath !== callerPath) return [];
      const importedName = bindingMatch(binding, edge.callee);
      return importedName ? [{ binding, importedName }] : [];
    });
    if (matches.length !== 1) continue;
    const match = matches[0];
    if (!match) continue;

    const source = await sourceForPath(root, callerPath, sourceCache);
    if (source === undefined || callerShadowsBinding(source, caller.line, edge.line, match.binding.localName)) continue;

    const targets = functionsByPathAndName.get(`${normalizedPath(match.binding.targetPath)}\u0000${match.importedName}`) ?? [];
    if (targets.length !== 1) continue;
    const target = targets[0];
    if (!target) continue;
    links.push({
      from: edge.from,
      line: edge.line,
      callee: edge.callee,
      target,
      targetPath: normalizedPath(match.binding.targetPath),
      importedName: match.importedName,
      bindingKind: match.binding.kind,
      evidence: "explicit-import-binding-to-unique-local-function",
    });
  }

  links.sort((a, b) => a.from.localeCompare(b.from) || a.line - b.line || a.callee.localeCompare(b.callee));
  return {
    schemaVersion: 1,
    links,
    linkedCallCount: links.length,
    interpretation: "cross-module-import-call-evidence-only",
  };
}
