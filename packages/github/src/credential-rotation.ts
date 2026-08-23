export type SynSecGitHubAppCredentialRotationKind = "webhook-secret" | "app-private-key";

export interface SynSecGitHubAppCredentialRotationInput {
  kind: SynSecGitHubAppCredentialRotationKind;
  replacementActivated?: boolean;
  runtimeReloaded?: boolean;
  externalConfigurationUpdated?: boolean;
  verificationSucceeded?: boolean;
}

export interface SynSecGitHubAppCredentialRotationPlan {
  version: 1;
  kind: SynSecGitHubAppCredentialRotationKind;
  readyToRetirePrevious: boolean;
  completedSteps: string[];
  requiredActions: string[];
  interpretation: "operator-acknowledged-rotation-state-not-secret-management";
}

const STEP_LIMIT = 8;

function ensureBoolean(value: boolean | undefined, name: string): boolean {
  if (value === undefined) return false;
  if (typeof value !== "boolean") throw new Error(`${name} must be boolean when supplied.`);
  return value;
}

function appendBounded(target: string[], value: string): void {
  if (target.length >= STEP_LIMIT) throw new Error("GitHub App credential rotation plan exceeds its bounded step count.");
  target.push(value);
}

/**
 * Build a deterministic, secret-free rollout plan for GitHub App credential rotation.
 *
 * This helper accepts only operator acknowledgements. It never accepts credential values, contacts
 * GitHub, reloads a process, revokes a key, or changes webhook configuration. The previous credential
 * is considered safe to retire only after every required rollout and verification acknowledgement is
 * present. Callers must derive acknowledgements from their own deployment and GitHub observations.
 */
export function buildSynSecGitHubAppCredentialRotationPlan(
  input: SynSecGitHubAppCredentialRotationInput,
): SynSecGitHubAppCredentialRotationPlan {
  if (input.kind !== "webhook-secret" && input.kind !== "app-private-key") {
    throw new Error("GitHub App credential rotation kind must be webhook-secret or app-private-key.");
  }

  const replacementActivated = ensureBoolean(input.replacementActivated, "replacementActivated");
  const runtimeReloaded = ensureBoolean(input.runtimeReloaded, "runtimeReloaded");
  const externalConfigurationUpdated = ensureBoolean(
    input.externalConfigurationUpdated,
    "externalConfigurationUpdated",
  );
  const verificationSucceeded = ensureBoolean(input.verificationSucceeded, "verificationSucceeded");
  const completedSteps: string[] = [];
  const requiredActions: string[] = [];

  if (replacementActivated) {
    appendBounded(completedSteps, input.kind === "webhook-secret"
      ? "Replacement webhook secret is staged in the runtime overlap set."
      : "Replacement GitHub App private key is active in GitHub.");
  } else {
    appendBounded(requiredActions, input.kind === "webhook-secret"
      ? "Stage the replacement webhook secret alongside the previous secret in the bounded two-secret overlap set."
      : "Activate the replacement GitHub App private key in GitHub before changing the SynSec runtime.");
  }

  if (runtimeReloaded) {
    appendBounded(completedSteps, "SynSec runtime has reloaded the replacement credential configuration.");
  } else {
    appendBounded(requiredActions, "Reload or roll the SynSec runtime with the replacement credential configuration.");
  }

  if (input.kind === "webhook-secret") {
    if (externalConfigurationUpdated) {
      appendBounded(completedSteps, "GitHub webhook configuration has been updated to use the replacement secret.");
    } else {
      appendBounded(requiredActions, "Update the GitHub webhook secret only after the replacement is staged in SynSec.");
    }
  } else if (externalConfigurationUpdated) {
    appendBounded(completedSteps, "GitHub-side replacement private-key activation has been operator-confirmed.");
  }

  if (verificationSucceeded) {
    appendBounded(completedSteps, input.kind === "webhook-secret"
      ? "An authenticated GitHub webhook delivery succeeded after the GitHub-side update."
      : "A fresh installation-token exchange succeeded after the SynSec runtime reload.");
  } else {
    appendBounded(requiredActions, input.kind === "webhook-secret"
      ? "Confirm at least one authenticated GitHub webhook delivery after the GitHub-side secret update."
      : "Verify a fresh installation-token exchange using the replacement private key.");
  }

  const readyToRetirePrevious = replacementActivated
    && runtimeReloaded
    && verificationSucceeded
    && (input.kind === "app-private-key" || externalConfigurationUpdated);

  if (!readyToRetirePrevious) {
    appendBounded(requiredActions, input.kind === "webhook-secret"
      ? "Keep the previous webhook secret in the overlap set until every required acknowledgement is complete."
      : "Keep the previous GitHub App private key active until every required acknowledgement is complete.");
  }

  return {
    version: 1,
    kind: input.kind,
    readyToRetirePrevious,
    completedSteps,
    requiredActions,
    interpretation: "operator-acknowledged-rotation-state-not-secret-management",
  };
}
