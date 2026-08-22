import { posix } from "node:path";
import type { IndexFileInput } from "./analysis.js";
import type { ModuleGraph } from "./module-graph.js";

export type TestOwnershipReason = "direct-import" | "filename-convention";

export interface LikelyTestOwner {
  path: string;
  reasons: TestOwnershipReason[];
}

export interface TestOwnershipContext {
  sourcePath: string;
  likelyTests: LikelyTestOwner[];
  maxResults: number;
  /** Heuristics identify likely related tests; they do not prove execution or coverage. */
  interpretation: "likely-test-ownership-only";
}

function normalize(value: string): string {
  return posix.normalize(value.replaceAll("\\", "/").replace(/^\.\//, "")).replace(/^\//, "");
}

function isTestPath(path: string): boolean {
  const value = normalize(path).toLowerCase();
  const base = posix.basename(value);
  return value.includes("/__tests__/")
    || value.startsWith("tests/")
    || value.startsWith("test/")
    || /(?:^|\.)(?:test|spec)\.[^.]+$/.test(base)
    || /^test_[^.]+\.py$/.test(base)
    || /_test\.go$/.test(base);
}

function filenameStem(path: string): string {
  const base = posix.basename(normalize(path)).toLowerCase();
  return base
    .replace(/(?:\.test|\.spec)(?=\.)/, "")
    .replace(/^test_/, "")
    .replace(/_test(?=\.)/, "")
    .replace(/\.[^.]+$/, "");
}

function conventionMatch(sourcePath: string, testPath: string): boolean {
  if (!isTestPath(testPath)) return false;
  const sourceStem = filenameStem(sourcePath);
  const testStem = filenameStem(testPath);
  return Boolean(sourceStem && sourceStem === testStem);
}

export function findLikelyTestOwners(
  graph: ModuleGraph,
  files: readonly IndexFileInput[],
  sourcePath: string,
  options: { maxResults?: number } = {},
): TestOwnershipContext {
  const normalizedSource = normalize(sourcePath);
  const maxResults = Math.max(0, Math.min(100, options.maxResults ?? 20));
  const reasons = new Map<string, Set<TestOwnershipReason>>();

  for (const edge of graph.edges) {
    if (!edge.target || normalize(edge.target).toLowerCase() !== normalizedSource.toLowerCase()) continue;
    const from = normalize(edge.from);
    if (!isTestPath(from)) continue;
    const entry = reasons.get(from) ?? new Set<TestOwnershipReason>();
    entry.add("direct-import");
    reasons.set(from, entry);
  }

  for (const file of files) {
    const path = normalize(file.path);
    if (path.toLowerCase() === normalizedSource.toLowerCase() || !conventionMatch(normalizedSource, path)) continue;
    const entry = reasons.get(path) ?? new Set<TestOwnershipReason>();
    entry.add("filename-convention");
    reasons.set(path, entry);
  }

  const priority: Record<TestOwnershipReason, number> = {
    "direct-import": 2,
    "filename-convention": 1,
  };
  const likelyTests = [...reasons.entries()]
    .map(([path, values]): LikelyTestOwner => ({
      path,
      reasons: [...values].sort((a, b) => priority[b] - priority[a] || a.localeCompare(b)),
    }))
    .sort((a, b) => {
      const direct = Number(b.reasons.includes("direct-import")) - Number(a.reasons.includes("direct-import"));
      if (direct !== 0) return direct;
      const reasonCount = b.reasons.length - a.reasons.length;
      return reasonCount || a.path.localeCompare(b.path);
    })
    .slice(0, maxResults);

  return {
    sourcePath: normalizedSource,
    likelyTests,
    maxResults,
    interpretation: "likely-test-ownership-only",
  };
}
