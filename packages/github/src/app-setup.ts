import type { GitHubInstallationPermissionLevel } from "./app.js";
import { requiredGitHubAppWorkerPermissions } from "./app-permissions.js";

export type SynSecGitHubAppEvent =
  | "installation"
  | "installation_repositories"
  | "pull_request"
  | "push";

export interface SynSecGitHubAppSetupOptions {
  publishSarif?: boolean;
  enableRemediationPullRequests?: boolean;
}

export interface SynSecGitHubAppSetupContract {
  version: 1;
  permissions: Record<string, GitHubInstallationPermissionLevel>;
  events: SynSecGitHubAppEvent[];
  remediationWriteEnabled: boolean;
  notes: string[];
}

function mergePermission(
  permissions: Record<string, GitHubInstallationPermissionLevel>,
  permission: string,
  level: GitHubInstallationPermissionLevel,
): void {
  const current = permissions[permission];
  if (current === "write" || current === level) return;
  permissions[permission] = level;
}

/**
 * Return the minimum GitHub App installation contract for the enabled SynSec features.
 *
 * Remediation write permissions are deliberately opt-in. Enabling repository scanning alone never
 * causes this helper to recommend contents:write or pull_requests:write. The returned object is a
 * setup description only; it does not create, update, or broaden a GitHub App installation.
 */
export function buildSynSecGitHubAppSetupContract(
  options: SynSecGitHubAppSetupOptions = {},
): SynSecGitHubAppSetupContract {
  const permissions: Record<string, GitHubInstallationPermissionLevel> = {};
  for (const requirement of requiredGitHubAppWorkerPermissions({ publishSarif: options.publishSarif })) {
    mergePermission(permissions, requirement.permission, requirement.level);
  }

  const remediationWriteEnabled = options.enableRemediationPullRequests === true;
  if (remediationWriteEnabled) {
    mergePermission(permissions, "contents", "write");
    mergePermission(permissions, "pull_requests", "write");
  }

  const events: SynSecGitHubAppEvent[] = [
    "installation",
    "installation_repositories",
    "pull_request",
    "push",
  ];

  return {
    version: 1,
    permissions,
    events,
    remediationWriteEnabled,
    notes: [
      "Subscribe only to the listed repository/install events used by SynSec intake.",
      options.publishSarif
        ? "security_events:write is required because SARIF publication is enabled."
        : "security_events permission is not required when SARIF publication is disabled.",
      remediationWriteEnabled
        ? "contents:write and pull_requests:write are required only for explicitly approved remediation PR creation."
        : "Repository remediation writes are disabled; contents:read is sufficient for acquisition.",
    ],
  };
}
