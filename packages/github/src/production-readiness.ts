import {
  validateGitHubAppDeployment,
  type GitHubAppDeploymentConfig,
  type GitHubAppDeploymentReadiness,
} from "./app-deployment.js";
import {
  assessGitHubAppSharedStateConformanceEvidence,
  type GitHubAppSharedStateEvidenceAssessment,
} from "./shared-state-evidence.js";

export interface GitHubAppProductionReadiness {
  ready: boolean;
  deployment: GitHubAppDeploymentReadiness;
  requiresSharedStateEvidence: boolean;
  sharedStateEvidence?: GitHubAppSharedStateEvidenceAssessment;
}

/**
 * Compose deployment configuration checks with portable shared-state conformance evidence.
 *
 * A single-replica deployment retains the existing deployment preflight behavior. A valid
 * multi-replica declaration is not sufficient on its own: the exact shared backend adapter build
 * must also have complete, identity-bound conformance evidence. This function does not connect to
 * GitHub or a database and never includes credential values in its result.
 */
export function assessGitHubAppProductionReadiness(
  config: GitHubAppDeploymentConfig,
  backendContract?: unknown,
  conformanceReport?: unknown,
): GitHubAppProductionReadiness {
  const deployment = validateGitHubAppDeployment(config);
  const replicaCount = config.replicaCount ?? 1;
  const requiresSharedStateEvidence = Number.isSafeInteger(replicaCount) && replicaCount > 1;

  if (!requiresSharedStateEvidence) {
    return {
      ready: deployment.ready,
      deployment,
      requiresSharedStateEvidence: false,
    };
  }

  const sharedStateEvidence = assessGitHubAppSharedStateConformanceEvidence(
    backendContract,
    conformanceReport,
  );
  return {
    ready: deployment.ready && sharedStateEvidence.ready,
    deployment,
    requiresSharedStateEvidence: true,
    sharedStateEvidence,
  };
}

export function assertGitHubAppProductionReady(
  config: GitHubAppDeploymentConfig,
  backendContract?: unknown,
  conformanceReport?: unknown,
): void {
  const readiness = assessGitHubAppProductionReadiness(config, backendContract, conformanceReport);
  if (readiness.ready) return;

  const deploymentCodes = readiness.deployment.issues
    .filter((issue) => issue.level === "error")
    .map((issue) => issue.code);
  const evidenceCodes = readiness.sharedStateEvidence?.issues.map((issue) => issue.code) ?? [];
  const codes = [...deploymentCodes, ...evidenceCodes];
  throw new Error(`GitHub App production readiness failed: ${codes.join(", ") || "shared-state-evidence-required"}`);
}
