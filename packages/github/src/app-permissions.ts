import type {
  GitHubInstallationPermissionLevel,
  GitHubInstallationPermissions,
} from "./app.js";

export interface GitHubAppPermissionRequirement {
  permission: string;
  level: GitHubInstallationPermissionLevel;
  purpose: "repository-acquisition" | "check-publication" | "sarif-publication";
}

export interface GitHubAppPermissionDiagnostic extends GitHubAppPermissionRequirement {
  actual?: GitHubInstallationPermissionLevel;
  status: "satisfied" | "missing" | "insufficient" | "unknown";
  message: string;
}

export interface GitHubAppPermissionDiagnosticResult {
  ok: boolean;
  metadataAvailable: boolean;
  required: GitHubAppPermissionRequirement[];
  diagnostics: GitHubAppPermissionDiagnostic[];
}

function satisfies(actual: GitHubInstallationPermissionLevel | undefined, required: GitHubInstallationPermissionLevel): boolean {
  if (required === "read") return actual === "read" || actual === "write";
  return actual === "write";
}

/** Return the minimum token permissions used by SynSec's current hosted worker operations. */
export function requiredGitHubAppWorkerPermissions(options: { publishSarif?: boolean } = {}): GitHubAppPermissionRequirement[] {
  return [
    { permission: "contents", level: "read", purpose: "repository-acquisition" },
    { permission: "checks", level: "write", purpose: "check-publication" },
    ...(options.publishSarif
      ? [{ permission: "security_events", level: "write", purpose: "sarif-publication" } as const]
      : []),
  ];
}

/**
 * Explain whether GitHub-reported installation-token permissions satisfy SynSec worker needs.
 *
 * Missing permission metadata is reported as unknown and `ok=false`; SynSec never interprets an
 * unavailable permission map as authorization to continue. This diagnostic describes existing
 * permissions only and does not request, broaden, or mutate installation access.
 */
export function diagnoseGitHubAppWorkerPermissions(
  permissions: GitHubInstallationPermissions | undefined,
  options: { publishSarif?: boolean } = {},
): GitHubAppPermissionDiagnosticResult {
  const required = requiredGitHubAppWorkerPermissions(options);
  const metadataAvailable = permissions !== undefined;
  const diagnostics = required.map((requirement): GitHubAppPermissionDiagnostic => {
    const actual = permissions?.[requirement.permission];
    if (!metadataAvailable) {
      return {
        ...requirement,
        status: "unknown",
        message: `GitHub did not provide permission metadata for ${requirement.permission}:${requirement.level}.`,
      };
    }
    if (actual === undefined) {
      return {
        ...requirement,
        status: "missing",
        message: `Missing GitHub App permission ${requirement.permission}:${requirement.level} for ${requirement.purpose}.`,
      };
    }
    if (!satisfies(actual, requirement.level)) {
      return {
        ...requirement,
        actual,
        status: "insufficient",
        message: `GitHub App permission ${requirement.permission}:${actual} is insufficient; ${requirement.level} is required for ${requirement.purpose}.`,
      };
    }
    return {
      ...requirement,
      actual,
      status: "satisfied",
      message: `GitHub App permission ${requirement.permission}:${actual} satisfies ${requirement.purpose}.`,
    };
  });

  return {
    ok: diagnostics.every((diagnostic) => diagnostic.status === "satisfied"),
    metadataAvailable,
    required,
    diagnostics,
  };
}
