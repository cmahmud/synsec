import { lstat } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { IndexFileInput, RepositoryIndex } from "./analysis.js";
import { buildCallGraph, type CallGraph } from "./call-graph.js";
import { buildImportCallLinkGraph, type ImportCallLinkGraph } from "./import-call-links.js";
import type { ModuleGraph } from "./module-graph.js";
import { resolveRouteEntrypoints, type RouteEntrypoint } from "./route-entrypoints.js";
import {
  repositoryRouteSinkFlowContexts,
  type RouteSinkFlowContext,
  type RouteSinkFlowOptions,
} from "./route-sink-flow.js";

export interface RepositoryRouteFlowAnalysis {
  callGraph: CallGraph;
  importCallLinks: ImportCallLinkGraph;
  entrypoints: RouteEntrypoint[];
  routeFlows: RouteSinkFlowContext[];
  analyzedFileCount: number;
  skippedUnsafeFileCount: number;
  /** All relationships are bounded static repository evidence only. */
  interpretation: "repository-structural-route-flow-evidence-only";
}

export interface RepositoryRouteFlowAnalysisOptions {
  maxDeclarationDistance?: number;
  maxCallDepth?: number;
  maxCallNodes?: number;
  maxEvidence?: number;
  maxRoutes?: number;
}

function insideRoot(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

async function safeAnalysisFiles(rootPath: string, files: readonly IndexFileInput[]): Promise<IndexFileInput[]> {
  const root = resolve(rootPath);
  const output: IndexFileInput[] = [];
  for (const file of files.slice(0, 5_000)) {
    if (typeof file.path !== "string" || !file.path || file.path.includes("\0") || isAbsolute(file.path)) continue;
    const candidate = resolve(root, file.path);
    if (!insideRoot(root, candidate)) continue;
    const info = await lstat(candidate).catch(() => undefined);
    if (!info?.isFile() || info.isSymbolicLink()) continue;
    output.push({ path: file.path, size: info.size });
  }
  return output;
}

/**
 * Build the complete defensive route-flow context from already-indexed repository files.
 *
 * The module graph must come from the same repository index/file inventory. The function does
 * not perform network access, execute repository code, or broaden analysis beyond the supplied
 * repository files. It independently rejects path escape, missing/non-regular files, and symlink
 * entries before lexical source analysis. Ambiguous imports and calls remain unresolved.
 */
export async function buildRepositoryRouteFlowAnalysis(
  rootPath: string,
  files: readonly IndexFileInput[],
  index: RepositoryIndex,
  moduleGraph: ModuleGraph,
  options: RepositoryRouteFlowAnalysisOptions = {},
): Promise<RepositoryRouteFlowAnalysis> {
  const maxCallNodes = Math.max(1, Math.min(1_000, options.maxCallNodes ?? 100));
  const safeFiles = await safeAnalysisFiles(rootPath, files);
  const callGraph = await buildCallGraph(rootPath, safeFiles);
  const importCallLinks = await buildImportCallLinkGraph(rootPath, safeFiles, moduleGraph, callGraph);
  const entrypoints = resolveRouteEntrypoints(index, callGraph, {
    ...(options.maxDeclarationDistance !== undefined ? { maxDeclarationDistance: options.maxDeclarationDistance } : {}),
    ...(options.maxCallDepth !== undefined ? { maxCallDepth: options.maxCallDepth } : {}),
    maxCallNodes,
  });
  const flowOptions: RouteSinkFlowOptions = {
    importCallLinks,
    maxCallNodes,
    ...(options.maxEvidence !== undefined ? { maxEvidence: options.maxEvidence } : {}),
    ...(options.maxRoutes !== undefined ? { maxRoutes: options.maxRoutes } : {}),
  };
  const routeFlows = repositoryRouteSinkFlowContexts(index, entrypoints, callGraph, flowOptions);

  return {
    callGraph,
    importCallLinks,
    entrypoints,
    routeFlows,
    analyzedFileCount: safeFiles.length,
    skippedUnsafeFileCount: Math.min(files.length, 5_000) - safeFiles.length,
    interpretation: "repository-structural-route-flow-evidence-only",
  };
}
