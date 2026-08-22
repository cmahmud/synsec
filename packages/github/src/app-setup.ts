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

export interface SynSecGitHubAppSetupEvaluation {
  version: 1;
  ready: boolean;
  missingPermissions: Array<{
    permission: string;
    required: GitHubInstallationPermissionLevel;
    actual?: GitHubInstallationPermissionLevel;
  }>;
  excessiveWritePermissions: string[];
  missingEvents: SynSecGitHubAppEvent[];
  extraEvents: string[];
  interpretation: "setup-comparison-not-runtime-authorization";
}

export interface SynSecGitHubAppSetupRecoveryPlan {
  version: 1;
  ready: boolean;
  requiredActions: string[];
  leastPrivilegeReview: string[];
  interpretation: "operator-guidance-not-runtime-authorization";
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

function permissionSatisfies(
  actual: GitHubInstallationPermissionLevel | undefined,
  required: GitHubInstallationPermissionLevel,
): boolean {
  return actual === "write" || actual === required;
}

function normalizedPermissions(
  value: Record<string, GitHubInstallationPermissionLevel | undefined>,
): Record<string, GitHubInstallationPermissionLevel> {
  const entries = Object.entries(value);
  if (entries.length > 100) throw new Error("GitHub App setup permission list exceeds 100 entries.");
  const result: Record<string, GitHubInstallationPermissionLevel> = {};
  for (const [name, level] of entries) {
    const permission = name.trim();
    if (!permission || permission.length > 128 || !/^[a-z0-9_]+$/i.test(permission)) {
      throw new Error("GitHub App setup contains an invalid permission name.");
    }
    if (level !== "read" && level !== "write") {
      throw new Error(`GitHub App permission ${permission} must be read or write.`);
    }
    result[permission] = level;
  }
  return result;
}

function normalizedEvents(value: readonly string[]): string[] {
  if (value.length > 100) throw new Error("GitHub App setup event list exceeds 100 entries.");
  const events = value.map((entry) => {
    const event = entry.trim();
    if (!event || event.length > 128 || !/^[a-z0-9_]+$/i.test(event)) {
      throw new Error("GitHub App setup contains an invalid event name.");
    }
    return event;
  });
  return [...new Set(events)].sort();
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

/**
 * Compare an operator-declared GitHub App configuration with SynSec's feature-aware minimum.
 *
 * Missing permission/event capability makes the comparison not ready. Extra subscriptions and
 * write permissions are reported separately as least-privilege drift; they do not prove runtime
 * authorization and this helper never contacts GitHub or mutates App settings.
 */
export function evaluateSynSecGitHubAppSetup(input: {
  permissions: Record<string, GitHubInstallationPermissionLevel | undefined>;
  events: readonly string[];
  options?: SynSecGitHubAppSetupOptions;
}): SynSecGitHubAppSetupEvaluation {
  const expected = buildSynSecGitHubAppSetupContract(input.options);
  const actualPermissions = normalizedPermissions(input.permissions);
  const actualEvents = normalizedEvents(input.events);
  const expectedEvents = new Set<string>(expected.events);

  const missingPermissions = Object.entries(expected.permissions)
    .filter(([permission, required]) => !permissionSatisfies(actualPermissions[permission], required))
    .map(([permission, required]) => ({
      permission,
      required,
      ...(actualPermissions[permission] ? { actual: actualPermissions[permission] } : {}),
    }));
  const excessiveWritePermissions = Object.entries(actualPermissions)
    .filter(([permission, level]) => level === "write" && expected.permissions[permission] !== "write")
    .map(([permission]) => permission)
    .sort();
  const missingEvents = expected.events.filter((event) => !actualEvents.includes(event));
  const extraEvents = actualEvents.filter((event) => !expectedEvents.has(event));

  return {
    version: 1,
    ready: missingPermissions.length === 0 && missingEvents.length === 0,
    missingPermissions,
    excessiveWritePermissions,
    missingEvents,
    extraEvents,
    interpretation: "setup-comparison-not-runtime-authorization",
  };
}

/**
 * Turn the bounded setup comparison into deterministic operator recovery guidance.
 *
 * Required actions address capabilities SynSec needs to operate. Least-privilege review items are
 * intentionally separate: they may be required by another operator-approved integration and are
 * never removed automatically. This helper is guidance only and does not contact or mutate GitHub.
 */
export function buildSynSecGitHubAppSetupRecoveryPlan(input: {
  permissions: Record<string, GitHubInstallationPermissionLevel | undefined>;
  events: readonly string[];
  options?: SynSecGitHubAppSetupOptions;
}): SynSecGitHubAppSetupRecoveryPlan {
  const evaluation = evaluateSynSecGitHubAppSetup(input);
  const requiredActions = [
    ...evaluation.missingPermissions.map(({ permission, required, actual }) =>
      actual
        ? `Upgrade GitHub App permission ${permission} from ${actual} to ${required}.`
        : `Add GitHub App permission ${permission}:${required}.`,
    ),
    ...evaluation.missingEvents.map((event) => `Subscribe the GitHub App to the ${event} event.`),
  ];
  const leastPrivilegeReview = [
    ...evaluation.excessiveWritePermissions.map(
      (permission) => `Review ${permission}:write and remove it if no other operator-approved feature requires it.`,
    ),
    ...evaluation.extraEvents.map(
      (event) => `Review the ${event} event subscription and remove it if no other operator-approved feature requires it.`,
    ),
  ];

  return {
    version: 1,
    ready: evaluation.ready,
    requiredActions,
    leastPrivilegeReview,
    interpretation: "operator-guidance-not-runtime-authorization",
  };
}
