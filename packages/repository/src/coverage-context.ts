import { isAbsolute, relative, resolve } from "node:path";
import type { Finding } from "@synsec/core";

export interface CoverageLine {
  line: number;
  hits: number;
}

export interface CoverageFile {
  path: string;
  lines: CoverageLine[];
}

export interface RepositoryCoverageIndex {
  schemaVersion: 1;
  format: "lcov";
  files: CoverageFile[];
  fileCount: number;
  lineCount: number;
  /** Coverage describes one supplied test run; it is not proof of production/runtime reachability. */
  interpretation: "observed-test-coverage-not-runtime-reachability";
}

export interface FindingCoverageContext {
  path?: string;
  line?: number;
  status: "executed" | "not-executed" | "no-data";
  hits?: number;
  interpretation: "observed-test-coverage-not-runtime-reachability";
}

export interface LcovParseOptions {
  repositoryRoot?: string;
}

const MAX_LCOV_BYTES = 16 * 1024 * 1024;
const MAX_COVERAGE_FILES = 10_000;
const MAX_COVERAGE_LINES = 1_000_000;
const MAX_PATH_LENGTH = 4096;
const MAX_LINE_NUMBER = 100_000_000;

function normalizePath(value: string, repositoryRoot?: string): string | undefined {
  const raw = value.trim();
  if (!raw || raw.length > MAX_PATH_LENGTH || raw.includes("\0")) return undefined;
  let normalized = raw.replaceAll("\\", "/");

  if (isAbsolute(raw)) {
    if (!repositoryRoot) return undefined;
    const root = resolve(repositoryRoot);
    const rel = relative(root, resolve(raw)).replaceAll("\\", "/");
    if (!rel || rel === ".." || rel.startsWith("../") || isAbsolute(rel)) return undefined;
    normalized = rel;
  }

  normalized = normalized.replace(/^\.\//, "").replace(/^\//, "");
  const pieces = normalized.split("/");
  if (pieces.some((piece) => piece === ".." || piece === "")) return undefined;
  return normalized;
}

function integer(value: string, label: string, max: number): number {
  if (!/^\d+$/.test(value)) throw new Error(`LCOV ${label} must be a non-negative integer.`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > max) throw new Error(`LCOV ${label} exceeds its supported bound.`);
  return parsed;
}

/**
 * Parse bounded LCOV text supplied by the operator or CI system.
 *
 * SynSec does not execute tests to create this data. Absolute source paths are accepted only when
 * an explicit repository root is supplied and the path resolves inside it; escaping/unusable
 * records are ignored rather than expanded outside repository scope.
 */
export function parseLcovCoverage(content: string, options: LcovParseOptions = {}): RepositoryCoverageIndex {
  if (Buffer.byteLength(content, "utf8") > MAX_LCOV_BYTES) {
    throw new Error(`LCOV input exceeds the ${MAX_LCOV_BYTES}-byte limit.`);
  }

  const files = new Map<string, Map<number, number>>();
  let currentPath: string | undefined;
  let lineCount = 0;

  for (const rawLine of content.split(/\r?\n/)) {
    if (rawLine.startsWith("SF:")) {
      currentPath = normalizePath(rawLine.slice(3), options.repositoryRoot);
      if (currentPath && !files.has(currentPath.toLowerCase())) {
        if (files.size >= MAX_COVERAGE_FILES) throw new Error(`LCOV input exceeds the ${MAX_COVERAGE_FILES}-file limit.`);
        files.set(currentPath.toLowerCase(), new Map());
      }
      continue;
    }
    if (rawLine === "end_of_record") {
      currentPath = undefined;
      continue;
    }
    if (!currentPath || !rawLine.startsWith("DA:")) continue;

    const [lineRaw, hitsRaw] = rawLine.slice(3).split(",", 3);
    if (lineRaw === undefined || hitsRaw === undefined) continue;
    const line = integer(lineRaw, "line number", MAX_LINE_NUMBER);
    const hits = integer(hitsRaw, "hit count", Number.MAX_SAFE_INTEGER);
    if (line <= 0) continue;

    const lines = files.get(currentPath.toLowerCase());
    if (!lines) continue;
    if (!lines.has(line)) {
      lineCount += 1;
      if (lineCount > MAX_COVERAGE_LINES) throw new Error(`LCOV input exceeds the ${MAX_COVERAGE_LINES}-line limit.`);
    }
    const previous = lines.get(line) ?? 0;
    lines.set(line, Math.min(Number.MAX_SAFE_INTEGER, previous + hits));
  }

  const normalizedFiles: CoverageFile[] = [...files.entries()]
    .map(([pathKey, lines]) => ({
      path: pathKey,
      lines: [...lines.entries()]
        .map(([line, hits]) => ({ line, hits }))
        .sort((a, b) => a.line - b.line),
    }))
    .sort((a, b) => a.path.localeCompare(b.path));

  return {
    schemaVersion: 1,
    format: "lcov",
    files: normalizedFiles,
    fileCount: normalizedFiles.length,
    lineCount,
    interpretation: "observed-test-coverage-not-runtime-reachability",
  };
}

export function findingCoverageContext(
  coverage: RepositoryCoverageIndex,
  finding: Finding,
): FindingCoverageContext {
  const path = finding.location?.path ? normalizePath(finding.location.path) : undefined;
  const line = finding.location?.startLine;
  if (!path || !line || !Number.isSafeInteger(line) || line <= 0) {
    return {
      ...(path ? { path } : {}),
      ...(line && Number.isSafeInteger(line) && line > 0 ? { line } : {}),
      status: "no-data",
      interpretation: "observed-test-coverage-not-runtime-reachability",
    };
  }

  const file = coverage.files.find((item) => item.path.toLowerCase() === path.toLowerCase());
  const covered = file?.lines.find((item) => item.line === line);
  if (!covered) {
    return {
      path,
      line,
      status: "no-data",
      interpretation: "observed-test-coverage-not-runtime-reachability",
    };
  }

  return {
    path,
    line,
    status: covered.hits > 0 ? "executed" : "not-executed",
    hits: covered.hits,
    interpretation: "observed-test-coverage-not-runtime-reachability",
  };
}
