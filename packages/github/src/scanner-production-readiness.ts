import {
  validateGitHubAppDeployment,
  type GitHubAppDeploymentConfig,
  type GitHubAppDeploymentReadiness,
} from "./app-deployment.js";
import {
  assessSynSecScannerIsolationProfile,
  type SynSecScannerIsolationAssessment,
  type SynSecScannerIsolationProfile,
} from "./scanner-isolation-profile.js";

export interface SynSecGitHubAppScannerProductionReadinessInput {
  deployment: GitHubAppDeploymentConfig;
  scannerIsolationProfile?: Partial<SynSecScannerIsolationProfile>;
}

export interface SynSecGitHubAppScannerProductionReadiness {
  ready: boolean;
  deployment: GitHubAppDeploymentReadiness;
  scannerIsolation: SynSecScannerIsolationAssessment;
  interpretation: "deployment-and-isolation-declarations-not-runtime-certification";
}

/**
 * Compose the existing hosted deployment preflight with the stricter scanner isolation profile.
 *
 * Production callers cannot accidentally obtain a ready result from the advisory scanner-isolation
 * mode: this function always re-validates deployment with `requireScannerIsolation: true` and also
 * requires the versioned isolation profile to be complete.
 */
export function assessGitHubAppScannerProductionReadiness(
  input: SynSecGitHubAppScannerProductionReadinessInput,
): SynSecGitHubAppScannerProductionReadiness {
  const deployment = validateGitHubAppDeployment({
    ...input.deployment,
    requireScannerIsolation: true,
  });
  const scannerIsolation = assessSynSecScannerIsolationProfile(input.scannerIsolationProfile);
  return {
    ready: deployment.ready && scannerIsolation.complete,
    deployment,
    scannerIsolation,
    interpretation: "deployment-and-isolation-declarations-not-runtime-certification",
  };
}

export function assertGitHubAppScannerProductionReady(
  input: SynSecGitHubAppScannerProductionReadinessInput,
): void {
  const readiness = assessGitHubAppScannerProductionReadiness(input);
  if (readiness.ready) return;

  const deploymentCodes = readiness.deployment.issues
    .filter((issue) => issue.level === "error")
    .map((issue) => issue.code);
  const isolationControls = readiness.scannerIsolation.missing;
  const diagnostics = [
    ...deploymentCodes.map((code) => `deployment:${code}`),
    ...isolationControls.map((control) => `scanner-isolation:${control}`),
  ];
  throw new Error(`GitHub App scanner production readiness failed: ${diagnostics.join(", ") || "unknown"}`);
}
