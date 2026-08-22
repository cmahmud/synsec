import { posix } from "node:path";
import { findModuleNeighborhood, type ModuleGraph } from "./module-graph.js";

export type IncrementalScanPlanReason =
  | "targeted-with-bounded-dependents"
  | "no-changes"
  | "invalid-changed-path"
  | "too-many-changed-files"
  | "high-impact-file-changed"
  | "changed-source-not-indexed"
  | "dependent-expansion-exceeded-bound";

export interface IncrementalScanPlan {
  mode: "targeted" | "full-repository";
  reason: IncrementalScanPlanReason;
  changedFiles: string[];
  selectedFiles: string[];
  dependentFiles: Array<{ path: string; depth: number; triggeredBy: string }>;
  maxDependentDepth: number;
  /** This plan is a coverage heuristic and never asserts that unselected files are safe. */
  interpretation: "coverage-heuristic-not-proof-of-unaffected-code";
}

export interface IncrementalScanPlanOptions {
  maxChangedFiles?: number;
  maxDependentDepth?: number;
  maxDependents?: number;
}

const DEFAULT_MAX_CHANGED_FILES = 500;
const DEFAULT_MAX_DEPENDENT_DEPTH = 2;
const DEFAULT_MAX_DEPENDENTS = 200;

const sourceExtensions = new Set([
  ".js", ".mjs", ".cjs", ".jsx",
  ".ts", ".mts", ".cts", ".tsx",
  ".py",
]);

const exactHighImpactFiles = new Set([
  "package.json",
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "bun.lockb",
  "pyproject.toml",
  "poetry.lock",
  "requirements.txt",
  "pipfile",
  "pipfile.lock",
  "go.mod",
  "go.sum",
  "cargo.toml",
  "cargo.lock",
  "composer.json",
  "composer.lock",
  "gemfile",
  "gemfile.lock",
  "dockerfile",
  "docker-compose.yml",
  "docker-compose.yaml",
  "compose.yml",
  "compose.yaml",
  "synsec.config.json",
]);

function boundedInteger(value: number | undefined, fallback: number, min: number, max: number, label: string): number {
  const normalized = value ?? fallback;
  if (!Number.isSafeInteger(normalized) || normalized < min || normalized > max) {
    throw new Error(`${label} must be an integer between ${min} and ${max}.`);
  }
  return normalized;
}

function normalizeRepositoryPath(value: string): string | undefined {
  if (typeof value !== "string" || value.includes("\0")) return undefined;
  const replaced = value.trim().replaceAll("\\", "/").replace(/^\.\//, "");
  if (!replaced || replaced.startsWith("/") || /^[A-Za-z]:\//.test(replaced)) return undefined;
  const normalized = posix.normalize(replaced);
  if (!normalized || normalized === "." || normalized === ".." || normalized.startsWith("../")) return undefined;
  return normalized;
}

function isHighImpactFile(path: string): boolean {
  const normalized = path.toLowerCase();
  const basename = posix.basename(normalized);
  if (exactHighImpactFiles.has(normalized) || exactHighImpactFiles.has(basename)) return true;
  if (normalized.startsWith(".github/workflows/")) return true;
  if (normalized.startsWith(".gitlab/")) return true;
  if (normalized.endsWith(".tf") || normalized.endsWith(".tfvars")) return true;
  if (/(^|\/)(tsconfig|jsconfig)(\.[^/]+)?\.json$/.test(normalized)) return true;
  return /(^|\/)(security|auth|permissions?|policy|policies)\.(json|ya?ml|toml)$/.test(normalized);
}

function isIndexedSource(path: string, nodes: ReadonlySet<string>): boolean {
  const extension = posix.extname(path).toLowerCase();
  return !sourceExtensions.has(extension) || nodes.has(path.toLowerCase());
}

function fullPlan(
  reason: Exclude<IncrementalScanPlanReason, "targeted-with-bounded-dependents" | "no-changes">,
  changedFiles: string[],
  maxDependentDepth: number,
): IncrementalScanPlan {
  return {
    mode: "full-repository",
    reason,
    changedFiles,
    selectedFiles: [],
    dependentFiles: [],
    maxDependentDepth,
    interpretation: "coverage-heuristic-not-proof-of-unaffected-code",
  };
}

/**
 * Build a conservative incremental-scan scope from changed files and structural module evidence.
 *
 * Direct changes are always selected. Known local dependents may be added to catch effects that
 * cross import boundaries, but this is only a coverage heuristic. Ambiguous/high-impact conditions
 * fail over to a full repository scan rather than treating unselected code as safe.
 */
export function buildIncrementalScanPlan(
  graph: ModuleGraph,
  changedFiles: readonly string[],
  options: IncrementalScanPlanOptions = {},
): IncrementalScanPlan {
  const maxChangedFiles = boundedInteger(options.maxChangedFiles, DEFAULT_MAX_CHANGED_FILES, 1, 10_000, "maxChangedFiles");
  const maxDependentDepth = boundedInteger(options.maxDependentDepth, DEFAULT_MAX_DEPENDENT_DEPTH, 0, 10, "maxDependentDepth");
  const maxDependents = boundedInteger(options.maxDependents, DEFAULT_MAX_DEPENDENTS, 1, 10_000, "maxDependents");

  const normalized: string[] = [];
  for (const value of changedFiles) {
    const path = normalizeRepositoryPath(value);
    if (!path) return fullPlan("invalid-changed-path", [...normalized], maxDependentDepth);
    normalized.push(path);
  }
  const changed = [...new Map(normalized.map((path) => [path.toLowerCase(), path])).values()].sort();

  if (changed.length === 0) {
    return {
      mode: "targeted",
      reason: "no-changes",
      changedFiles: [],
      selectedFiles: [],
      dependentFiles: [],
      maxDependentDepth,
      interpretation: "coverage-heuristic-not-proof-of-unaffected-code",
    };
  }
  if (changed.length > maxChangedFiles) return fullPlan("too-many-changed-files", changed, maxDependentDepth);
  if (changed.some(isHighImpactFile)) return fullPlan("high-impact-file-changed", changed, maxDependentDepth);

  const nodes = new Set(graph.nodes.map((path) => path.toLowerCase()));
  if (changed.some((path) => !isIndexedSource(path, nodes))) {
    return fullPlan("changed-source-not-indexed", changed, maxDependentDepth);
  }

  const dependents = new Map<string, { path: string; depth: number; triggeredBy: string }>();
  for (const path of changed) {
    if (!nodes.has(path.toLowerCase()) || maxDependentDepth === 0) continue;
    const neighborhood = findModuleNeighborhood(graph, path, maxDependentDepth, maxDependents + 1);
    if (neighborhood.dependents.length > maxDependents) {
      return fullPlan("dependent-expansion-exceeded-bound", changed, maxDependentDepth);
    }
    for (const dependent of neighborhood.dependents) {
      const key = dependent.path.toLowerCase();
      const previous = dependents.get(key);
      if (!previous || dependent.depth < previous.depth || (dependent.depth === previous.depth && path < previous.triggeredBy)) {
        dependents.set(key, { ...dependent, triggeredBy: path });
      }
    }
  }

  if (dependents.size > maxDependents) {
    return fullPlan("dependent-expansion-exceeded-bound", changed, maxDependentDepth);
  }

  const dependentFiles = [...dependents.values()]
    .filter((item) => !changed.some((path) => path.toLowerCase() === item.path.toLowerCase()))
    .sort((a, b) => a.depth - b.depth || a.path.localeCompare(b.path) || a.triggeredBy.localeCompare(b.triggeredBy));
  const selectedFiles = [...new Map(
    [...changed, ...dependentFiles.map((item) => item.path)].map((path) => [path.toLowerCase(), path]),
  ).values()].sort();

  return {
    mode: "targeted",
    reason: "targeted-with-bounded-dependents",
    changedFiles: changed,
    selectedFiles,
    dependentFiles,
    maxDependentDepth,
    interpretation: "coverage-heuristic-not-proof-of-unaffected-code",
  };
}
