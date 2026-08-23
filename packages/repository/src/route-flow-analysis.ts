import { lstat } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { IndexFileInput, RepositoryIndex } from "./analysis.js";
import { buildCallGraph, type CallGraph } from "./call-graph.js";
import { buildImportCallLinkGraph, type ImportCallLinkGraph } from "./import-call-links.js";
import { resolveImportedNodeRouteEntrypoints } from "./import-route-handlers.js";
import type { ModuleGraph } from "./module-graph.js";
import { resolveRouteEntrypoints, type RouteEntrypoint } from "./route-entrypoints.js";
import {
  repositoryRouteProtectionContexts,
  type RouteProtectionContext,
  type RouteProtectionOptions,
} from "./route-protection-context.js";
import {
  buildRouteSecurityReviewContexts,
  type RouteSecurityReviewContext,
} from "./route-security-review.js";
import {
  repositoryRouteSinkFlowContexts,
  type RouteSinkFlowContext,
  type RouteSinkFlowOptions,
} from "./route-sink-flow.js";

const DEFAULT_MAX_ANALYSIS_FILES = 5_000;
const MAX_ANALYSIS_FILES = 5_000;

export interface RepositoryRouteFlowAnalysis {
  callGraph: CallGraph;
  importCallLinks: ImportCallLinkGraph;
  entrypoints: RouteEntrypoint[];
  routeFlows: RouteSinkFlowContext[];
  routeProtectionContexts: RouteProtectionContext[];
  routeSecurityReviews: RouteSecurityReviewContext[];
  inputFileCount: number;
  analyzedFileCount: number;
  skippedUnsafeFileCount: number;
  truncatedFileCount: number;
  coverage: "complete-input" | "bounded-input";
  /** All relationships are bounded static repository evidence only. */
  interpretation: "repository-structural-route-flow-evidence-only";
}

export interface RepositoryRouteFlowAnalysisOptions {
  maxDeclarationDistance?: number;
  maxCallDepth?: number;
  maxCallNodes?: number;
  maxEvidence?: number;
  maxRoutes?: number;
  /** Maximum number of supplied repository files eligible for lexical analysis. */
  maxFiles?: number;
}

interface SafeAnalysisFileResult {
  files: IndexFileInput[];
  skippedUnsafeFileCount: number;
  truncatedFileCount: number;
}

function insideRoot(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

function boundedMaxFiles(value: number | undefined): number {
  if (value === undefined) return DEFAULT_MAX_ANALYSIS_FILES;
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_ANALYSIS_FILES) {
    throw new Error(`Repository route-flow maxFiles must be an integer between 1 and ${MAX_ANALYSIS_FILES}.`);
  }
  return value;
}

async function safeAnalysisFiles(
  rootPath: string,
  files: readonly IndexFileInput[],
  maxFiles: number,
): Promise<SafeAnalysisFileResult> {
  const root = resolve(rootPath);
  const output: IndexFileInput[] = [];
  let skippedUnsafeFileCount = 0;
  const eligible = files.slice(0, maxFiles);

  for (const file of eligible) {
    if (typeof file.path !== "string" || !file.path || file.path.includes("\0") || isAbsolute(file.path)) {
      skippedUnsafeFileCount += 1;
      continue;
    }
    const candidate = resolve(root, file.path);
    if (!insideRoot(root, candidate)) {
      skippedUnsafeFileCount += 1;
      continue;
    }
    const info = await lstat(candidate).catch(() => undefined);
    if (!info?.isFile() || info.isSymbolicLink()) {
      skippedUnsafeFileCount += 1;
      continue;
    }
    output.push({ path: file.path, size: info.size });
  }

  return {
    files: output,
    skippedUnsafeFileCount,
    truncatedFileCount: Math.max(0, files.length - eligible.length),
  };
}

/**
 * Build the complete defensive route-flow context from already-indexed repository files.
 *
 * The module graph must come from the same repository index/file inventory. The function does
 * not perform network access, execute repository code, or broaden analysis beyond the supplied
 * repository files. It independently rejects path escape, missing/non-regular files, and symlink
 * entries before lexical source analysis. Input above the configured file bound is explicitly
 * reported as bounded coverage rather than silently treated as analyzed. Ambiguous imports and
 * calls remain unresolved. Auth-related route protection and route-security review summaries are
 * structural review evidence only and never claims that a route is effectively protected or
 * reachable at runtime.
 */
export async function buildRepositoryRouteFlowAnalysis(
  rootPath: string,
  files: readonly IndexFileInput[],
  index: RepositoryIndex,
  moduleGraph: ModuleGraph,
  options: RepositoryRouteFlowAnalysisOptions = {},
): Promise<RepositoryRouteFlowAnalysis> {
  const maxCallNodes = Math.max(1, Math.min(1_000, options.maxCallNodes ?? 100));
  const maxFiles = boundedMaxFiles(options.maxFiles);
  const safe = await safeAnalysisFiles(rootPath, files, maxFiles);
  const callGraph = await buildCallGraph(rootPath, safe.files);
  const importCallLinks = await buildImportCallLinkGraph(rootPath, safe.files, moduleGraph, callGraph);
  let entrypoints = resolveRouteEntrypoints(index, callGraph, {
    ...(options.maxDeclarationDistance !== undefined ? { maxDeclarationDistance: options.maxDeclarationDistance } : {}),
    ...(options.maxCallDepth !== undefined ? { maxCallDepth: options.maxCallDepth } : {}),
    maxCallNodes,
  });
  entrypoints = await resolveImportedNodeRouteEntrypoints(
    rootPath,
    safe.files,
    moduleGraph,
    callGraph,
    entrypoints,
    {
      ...(options.maxCallDepth !== undefined ? { maxCallDepth: options.maxCallDepth } : {}),
      maxCallNodes,
    },
  );
  const flowOptions: RouteSinkFlowOptions = {
    importCallLinks,
    maxCallNodes,
    ...(options.maxEvidence !== undefined ? { maxEvidence: options.maxEvidence } : {}),
    ...(options.maxRoutes !== undefined ? { maxRoutes: options.maxRoutes } : {}),
  };
  const protectionOptions: RouteProtectionOptions = {
    importCallLinks,
    maxCallNodes,
    ...(options.maxEvidence !== undefined ? { maxEvidence: options.maxEvidence } : {}),
    ...(options.maxRoutes !== undefined ? { maxRoutes: options.maxRoutes } : {}),
  };
  const routeFlows = repositoryRouteSinkFlowContexts(index, entrypoints, callGraph, flowOptions);
  const routeProtectionContexts = repositoryRouteProtectionContexts(index, entrypoints, callGraph, protectionOptions);
  const routeSecurityReviews = buildRouteSecurityReviewContexts(
    routeFlows,
    routeProtectionContexts,
    options.maxRoutes ?? 1_000,
  );

  return {
    callGraph,
    importCallLinks,
    entrypoints,
    routeFlows,
    routeProtectionContexts,
    routeSecurityReviews,
    inputFileCount: files.length,
    analyzedFileCount: safe.files.length,
    skippedUnsafeFileCount: safe.skippedUnsafeFileCount,
    truncatedFileCount: safe.truncatedFileCount,
    coverage: safe.truncatedFileCount === 0 ? "complete-input" : "bounded-input",
    interpretation: "repository-structural-route-flow-evidence-only",
  };
}
