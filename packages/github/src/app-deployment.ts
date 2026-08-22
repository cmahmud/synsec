import { isAbsolute, relative, resolve } from "node:path";

export type GitHubAppTlsMode = "local" | "terminated-upstream" | "none";
export type GitHubAppDeploymentIssueLevel = "error" | "warning";

export interface GitHubAppDeploymentConfig {
  appId: number | string;
  privateKey: string;
  webhookSecret: string;
  listenHost: string;
  tlsMode: GitHubAppTlsMode;
  stateDirectory: string;
  workspaceDirectory: string;
}

export interface GitHubAppDeploymentIssue {
  level: GitHubAppDeploymentIssueLevel;
  code:
    | "invalid-app-id"
    | "invalid-private-key"
    | "weak-webhook-secret"
    | "invalid-listen-host"
    | "plaintext-public-listener"
    | "relative-state-directory"
    | "relative-workspace-directory"
    | "overlapping-runtime-directories";
  message: string;
}

export interface GitHubAppDeploymentReadiness {
  ready: boolean;
  issues: GitHubAppDeploymentIssue[];
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);

function isPositiveAppId(value: number | string): boolean {
  if (typeof value === "number") return Number.isSafeInteger(value) && value > 0;
  return /^[1-9]\d*$/.test(value.trim());
}

function looksLikePemPrivateKey(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.startsWith("-----BEGIN RSA PRIVATE KEY-----")) {
    return trimmed.endsWith("-----END RSA PRIVATE KEY-----");
  }
  if (trimmed.startsWith("-----BEGIN PRIVATE KEY-----")) {
    return trimmed.endsWith("-----END PRIVATE KEY-----");
  }
  return false;
}

function directoriesOverlap(left: string, right: string): boolean {
  const resolvedLeft = resolve(left);
  const resolvedRight = resolve(right);
  if (resolvedLeft === resolvedRight) return true;

  const leftToRight = relative(resolvedLeft, resolvedRight);
  const rightToLeft = relative(resolvedRight, resolvedLeft);
  const isDescendant = (value: string): boolean => Boolean(value) && !value.startsWith("..") && !isAbsolute(value);
  return isDescendant(leftToRight) || isDescendant(rightToLeft);
}

/**
 * Validate operator-controlled GitHub App deployment settings before a hosted runtime starts.
 *
 * The result deliberately contains only categorical diagnostics. Secret values and filesystem
 * contents are never echoed into messages, making the result safe to surface in startup logs.
 */
export function validateGitHubAppDeployment(
  config: GitHubAppDeploymentConfig,
): GitHubAppDeploymentReadiness {
  const issues: GitHubAppDeploymentIssue[] = [];
  const host = config.listenHost.trim().toLowerCase().replace(/^\[|\]$/g, "");

  if (!isPositiveAppId(config.appId)) {
    issues.push({
      level: "error",
      code: "invalid-app-id",
      message: "GitHub App ID must be a positive integer.",
    });
  }

  if (!looksLikePemPrivateKey(config.privateKey)) {
    issues.push({
      level: "error",
      code: "invalid-private-key",
      message: "GitHub App private key must be a PEM-encoded private key.",
    });
  }

  if (Buffer.byteLength(config.webhookSecret, "utf8") < 32) {
    issues.push({
      level: "error",
      code: "weak-webhook-secret",
      message: "Webhook secret must contain at least 32 bytes.",
    });
  }

  if (!host || host === "*" || /[\s/]/.test(host)) {
    issues.push({
      level: "error",
      code: "invalid-listen-host",
      message: "Listener host must be a host name or IP address, not a URL, wildcard, or path.",
    });
  } else if (config.tlsMode === "none" && !LOOPBACK_HOSTS.has(host)) {
    issues.push({
      level: "error",
      code: "plaintext-public-listener",
      message: "A non-loopback webhook listener requires local TLS or explicit upstream TLS termination.",
    });
  }

  if (!isAbsolute(config.stateDirectory)) {
    issues.push({
      level: "error",
      code: "relative-state-directory",
      message: "Durable state directory must be an absolute path.",
    });
  }

  if (!isAbsolute(config.workspaceDirectory)) {
    issues.push({
      level: "error",
      code: "relative-workspace-directory",
      message: "Repository workspace directory must be an absolute path.",
    });
  }

  if (
    isAbsolute(config.stateDirectory) &&
    isAbsolute(config.workspaceDirectory) &&
    directoriesOverlap(config.stateDirectory, config.workspaceDirectory)
  ) {
    issues.push({
      level: "error",
      code: "overlapping-runtime-directories",
      message: "Durable state and repository workspaces must use separate, non-nested directory trees.",
    });
  }

  return {
    ready: !issues.some((issue) => issue.level === "error"),
    issues,
  };
}

export function assertGitHubAppDeploymentReady(config: GitHubAppDeploymentConfig): void {
  const readiness = validateGitHubAppDeployment(config);
  if (readiness.ready) return;

  const codes = readiness.issues
    .filter((issue) => issue.level === "error")
    .map((issue) => issue.code)
    .join(", ");
  throw new Error(`GitHub App deployment configuration is not ready: ${codes}`);
}
