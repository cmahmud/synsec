import { lstat } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { IndexFileInput, RepositoryIndex } from "./analysis.js";
import { buildCallGraph, type CallGraph } from "./call-graph.js";
import { resolveDjangoRouteEntrypoints } from "./django-route-handlers.js";
import { composeDjangoIncludedRouteEntrypoints } from "./django-urlconf-composition.js";
import {
  buildFastApiRouteDependencyContexts,
  type FastApiRouteDependencyContext,
} from "./fastapi-route-dependencies.js";
import { buildImportCallLinkGraph, type ImportCallLinkGraph } from "./import-call-links.js";
import { resolveImportedNodeRouteEntrypoints } from "./import-route-handlers.js";
import type { ModuleGraph } from "./module-graph.js";
import {
  repositoryRouteRequestInputForwardingContexts,
  type RouteRequestInputForwardingContext,
} from "./request-input-forwarding.js";
import {
  collectRequestInputSignals,
  repositoryRouteRequestInputFlowContexts,
  type RequestInputSignal,
  type RouteRequestInputFlowContext,
} from "./request-input-flow.js";
import {
  repositoryRouteRequestInputReturnFlowContexts,
  type RouteRequestInputReturnFlowContext,
} from "./request-input-return-flow.js";
import { resolveRouteEntrypoints, type RouteEntrypoint } from "./route-entrypoints.js";
import {
  buildRouteMiddlewareCompositionContexts,
  type RouteMiddlewareCompositionContext,
} from "./route-middleware-composition.js";
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
  requestInputs: RequestInputSignal[];
  entrypoints: RouteEntrypoint[];
  routeMiddlewareContexts: RouteMiddlewareCompositionContext[];
  fastApiDependencyContexts: FastApiRouteDependencyContext[];
  routeFlows: RouteSinkFlowContext[];
  requestInputFlows: RouteRequestInputFlowContext[];
  requestInputForwardingFlows: RouteRequestInputForwardingContext[];
  requestInputReturnFlows: RouteRequestInputReturnFlowContext[];
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
  maxRequestInputSignals?: number;
  maxRequestInputForwardLines?: number;
  maxRequestInputReturnForwardLines?: number;
  maxDjangoIncludeDepth?: number;
  maxDjangoComposedRoutes?: number;
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
 * calls remain unresolved. Request-source flow requires an explicit framework request access,
 * unique lexical source/sink ownership, and a bounded directed call path. A separate forwarding
 * layer recognizes only simple immutable JS/TS request bindings passed unchanged once into one
 * resolved call; transformations, sanitization, aliasing, mutation, multiple use, and ambiguity
 * fail closed. A second, separately labeled return-flow layer recognizes only helpers with one
 * exact direct request-access return, one resolved helper invocation assigned to `const`, and one
 * unchanged direct-argument use of that return value before a bounded sink. It does not generalize
 * into variable-level taint or infer that parameter names establish request control. Explicit
 * all-named Node route registrations additionally receive bounded middleware composition evidence:
 * middleware identifiers resolve only to unique same-file functions or explicit repository-local
 * named imports, and shadowed/dynamic/ambiguous middleware stays unresolved. FastAPI route decorators
 * receive a separate dependency-composition layer only for literal route-level
 * `dependencies=[Depends(name), Security(name)]` lists with explicitly imported FastAPI wrappers.
 * Dependency identifiers resolve only to unique already-defined same-file Python functions or
 * unshadowed repository-local named imports; factories, dotted expressions, dynamic lists,
 * ambiguous targets, and shadowed names remain unresolved. Django URLConf `path()` registrations
 * receive view-function resolution only for a simple function identifier that maps uniquely to a
 * same-file function or an unshadowed explicit repository-local `from ... import ...` binding. A
 * separate bounded Django include layer composes route identities only for literal
 * `path("prefix/", include("module.urls"))` edges that resolve to exactly one supplied repository
 * Python file, starts from structural URLConf roots, bounds include depth/output, and rejects cycles,
 * ambiguous modules, and dynamic include forms. Dotted views, class-based `as_view()`, lambdas,
 * wildcard/parenthesized imports, and dynamic expressions remain unresolved. Included route
 * identities, FastAPI dependencies, middleware auth signals, resolved view calls, bounded callees,
 * and all request-flow layers remain structural context rather than proof that framework registration,
 * dependencies, ROOT_URLCONF, include(), middleware, views, or data flows execute at runtime.
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
  const requestInputs = await collectRequestInputSignals(rootPath, safe.files, {
    ...(options.maxRequestInputSignals !== undefined ? { maxSignals: options.maxRequestInputSignals } : {}),
  });
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
  entrypoints = await resolveDjangoRouteEntrypoints(
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
  entrypoints = await composeDjangoIncludedRouteEntrypoints(
    rootPath,
    safe.files,
    entrypoints,
    {
      ...(options.maxDjangoIncludeDepth !== undefined ? { maxIncludeDepth: options.maxDjangoIncludeDepth } : {}),
      ...(options.maxDjangoComposedRoutes !== undefined ? { maxComposedRoutes: options.maxDjangoComposedRoutes } : {}),
    },
  );
  const routeMiddlewareContexts = await buildRouteMiddlewareCompositionContexts(
    rootPath,
    safe.files,
    index,
    moduleGraph,
    callGraph,
    importCallLinks,
    entrypoints,
    {
      ...(options.maxRoutes !== undefined ? { maxRoutes: options.maxRoutes } : {}),
      ...(options.maxCallDepth !== undefined ? { maxCallDepth: options.maxCallDepth } : {}),
      maxCallNodes,
    },
  );
  const fastApiDependencyContexts = await buildFastApiRouteDependencyContexts(
    rootPath,
    safe.files,
    index,
    moduleGraph,
    callGraph,
    entrypoints,
    {
      ...(options.maxRoutes !== undefined ? { maxRoutes: options.maxRoutes } : {}),
      ...(options.maxCallDepth !== undefined ? { maxCallDepth: options.maxCallDepth } : {}),
      maxCallNodes,
      ...(options.maxEvidence !== undefined ? { maxEvidence: options.maxEvidence } : {}),
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
  const requestInputFlows = repositoryRouteRequestInputFlowContexts(
    index,
    requestInputs,
    entrypoints,
    callGraph,
    {
      importCallLinks,
      maxCallNodes,
      ...(options.maxEvidence !== undefined ? { maxEvidence: options.maxEvidence } : {}),
      ...(options.maxRoutes !== undefined ? { maxRoutes: options.maxRoutes } : {}),
    },
  );
  const requestInputForwardingFlows = await repositoryRouteRequestInputForwardingContexts(
    rootPath,
    safe.files,
    requestInputs,
    routeFlows,
    callGraph,
    importCallLinks,
    {
      maxCallNodes,
      ...(options.maxEvidence !== undefined ? { maxEvidence: options.maxEvidence } : {}),
      ...(options.maxRoutes !== undefined ? { maxRoutes: options.maxRoutes } : {}),
      ...(options.maxRequestInputForwardLines !== undefined
        ? { maxForwardLines: options.maxRequestInputForwardLines }
        : {}),
    },
  );
  const requestInputReturnFlows = await repositoryRouteRequestInputReturnFlowContexts(
    rootPath,
    safe.files,
    requestInputs,
    routeFlows,
    callGraph,
    importCallLinks,
    {
      maxCallNodes,
      ...(options.maxEvidence !== undefined ? { maxEvidence: options.maxEvidence } : {}),
      ...(options.maxRoutes !== undefined ? { maxRoutes: options.maxRoutes } : {}),
      ...(options.maxRequestInputReturnForwardLines !== undefined
        ? { maxForwardLines: options.maxRequestInputReturnForwardLines }
        : {}),
    },
  );
  const routeProtectionContexts = repositoryRouteProtectionContexts(index, entrypoints, callGraph, protectionOptions);
  const routeSecurityReviews = buildRouteSecurityReviewContexts(
    routeFlows,
    routeProtectionContexts,
    options.maxRoutes ?? 1_000,
  );

  return {
    callGraph,
    importCallLinks,
    requestInputs,
    entrypoints,
    routeMiddlewareContexts,
    fastApiDependencyContexts,
    routeFlows,
    requestInputFlows,
    requestInputForwardingFlows,
    requestInputReturnFlows,
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
