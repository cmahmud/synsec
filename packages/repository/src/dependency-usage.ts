import type { DependencyUsage, ModuleEdge, RepositoryIndex } from "./analysis.js";
import type { ModuleGraph, ResolvedModuleEdge } from "./module-graph.js";

export interface ExternalDependencyUsage extends DependencyUsage {
  excludedRepositoryLocalImportCount: number;
  /** Import syntax is useful triage evidence, but it does not establish runtime execution. */
  interpretation: "observed-import-evidence-not-runtime-reachability";
}

function moduleMatchesPackage(edge: ModuleEdge, packageName: string): boolean {
  const specifier = edge.specifier.toLowerCase();
  const normalized = packageName.toLowerCase();
  const pythonNormalized = normalized.replaceAll("-", "_");
  if (specifier === normalized || specifier.startsWith(`${normalized}/`)) return true;
  if (specifier === pythonNormalized || specifier.startsWith(`${pythonNormalized}.`)) return true;
  return false;
}

function edgeIdentity(edge: Pick<ModuleEdge, "from" | "specifier" | "kind" | "line">): string {
  return `${edge.from}\u0000${edge.kind}\u0000${edge.line}\u0000${edge.specifier}`;
}

/**
 * Report observed third-party package usage while excluding imports that the conservative module
 * resolver proved refer to repository files.
 *
 * This remains import evidence only. It does not prove that an imported dependency executes at
 * runtime, and unresolved imports remain eligible evidence rather than being guessed local.
 */
export function findExternalDependencyUsage(
  index: RepositoryIndex,
  graph: ModuleGraph,
  packageName: string,
  maxEvidence = 10,
): ExternalDependencyUsage {
  const boundedEvidence = Number.isSafeInteger(maxEvidence)
    ? Math.max(1, Math.min(100, maxEvidence))
    : 10;
  const localEdges = new Set(
    graph.edges
      .filter((edge): edge is ResolvedModuleEdge & { target: string } =>
        edge.resolution === "repository-file" && typeof edge.target === "string")
      .map(edgeIdentity),
  );
  const matching = index.moduleEdges.filter((edge) => moduleMatchesPackage(edge, packageName));
  const externalEvidence = matching.filter((edge) => !localEdges.has(edgeIdentity(edge)));
  const evidence = externalEvidence.slice(0, boundedEvidence);
  return {
    packageName,
    status: evidence.length > 0 ? "observed-import" : "unknown",
    evidence,
    excludedRepositoryLocalImportCount: matching.length - externalEvidence.length,
    interpretation: "observed-import-evidence-not-runtime-reachability",
  };
}
