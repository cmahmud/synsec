import { isAbsolute, relative, resolve } from "node:path";
import type { GitHubWebhookSecret } from "./app.js";

export type GitHubAppTlsMode = "local" | "terminated-upstream" | "none";
export type GitHubAppDeploymentIssueLevel = "error" | "warning";
export type GitHubAppScannerProcessBoundary = "container" | "sandbox" | "host";
export type GitHubAppScannerNetworkPolicy = "none" | "egress-filtered" | "host";
export type GitHubAppScannerRepositoryFilesystem = "read-only" | "writable";

export interface GitHubAppScannerIsolationConfig {
  processBoundary: GitHubAppScannerProcessBoundary;
  cpuLimit: boolean;
  memoryLimit: boolean;
  networkPolicy: GitHubAppScannerNetworkPolicy;
  repositoryFilesystem: GitHubAppScannerRepositoryFilesystem;
}

export interface GitHubAppDeploymentConfig {
  appId: number | string;
  privateKey: string;
  webhookSecret: GitHubWebhookSecret;
  listenHost: string;
  tlsMode: GitHubAppTlsMode;
  stateDirectory: string;
  workspaceDirectory: string;
  scannerIsolation?: GitHubAppScannerIsolationConfig;
  /** Fail deployment readiness when scanner isolation is absent or incomplete. */
  requireScannerIsolation?: boolean;
}

export interface GitHubAppDeploymentIssue {
  level: GitHubAppDeploymentIssueLevel;
  code:
    | "invalid-app-id"
    | "invalid-private-key"
    | "invalid-webhook-secret-set"
    | "weak-webhook-secret"
    | "invalid-listen-host"
    | "plaintext-public-listener"
    | "relative-state-directory"
    | "relative-workspace-directory"
    | "overlapping-runtime-directories"
    | "scanner-isolation-missing"
    | "scanner-process-unisolated"
    | "scanner-resource-limits-missing"
    | "scanner-network-unrestricted"
    | "scanner-repository-writable";
  message: string;
}

export interface GitHubAppDeploymentReadiness {
  ready: boolean;
  issues: GitHubAppDeploymentIssue[];
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);
const MAX_WEBHOOK_SECRET_BYTES = 4096;

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

function isolationLevel(config: GitHubAppDeploymentConfig): GitHubAppDeploymentIssueLevel {
  return config.requireScannerIsolation ? "error" : "warning";
}

function validateWebhookSecrets(config: GitHubAppDeploymentConfig, issues: GitHubAppDeploymentIssue[]): void {
  const secrets = typeof config.webhookSecret === "string" ? [config.webhookSecret] : [...config.webhookSecret];
  if (secrets.length < 1 || secrets.length > 2 || new Set(secrets.map((secret) => secret.trim())).size !== secrets.length) {
    issues.push({
      level: "error",
      code: "invalid-webhook-secret-set",
      message: "Webhook verification requires one secret, or exactly two distinct secrets during rotation overlap.",
    });
    return;
  }
  if (secrets.some((secret) => {
    const bytes = Buffer.byteLength(secret, "utf8");
    return bytes < 32 || bytes > MAX_WEBHOOK_SECRET_BYTES;
  })) {
    issues.push({
      level: "error",
      code: "weak-webhook-secret",
      message: `Every webhook secret must contain between 32 and ${MAX_WEBHOOK_SECRET_BYTES} bytes.`,
    });
  }
}

function validateScannerIsolation(config: GitHubAppDeploymentConfig, issues: GitHubAppDeploymentIssue[]): void {
  const level = isolationLevel(config);
  const isolation = config.scannerIsolation;
  if (!isolation) {
    issues.push({
      level,
      code: "scanner-isolation-missing",
      message: "Scanner process/resource/network/filesystem isolation has not been declared for this deployment.",
    });
    return;
  }

  if (isolation.processBoundary === "host") {
    issues.push({
      level,
      code: "scanner-process-unisolated",
      message: "Scanner execution must use a container or equivalent sandbox boundary for production isolation.",
    });
  }
  if (!isolation.cpuLimit || !isolation.memoryLimit) {
    issues.push({
      level,
      code: "scanner-resource-limits-missing",
      message: "Scanner execution must declare both CPU and memory limits.",
    });
  }
  if (isolation.networkPolicy === "host") {
    issues.push({
      level,
      code: "scanner-network-unrestricted",
      message: "Scanner execution must disable network access or use an explicit egress-filtered network policy.",
    });
  }
  if (isolation.repositoryFilesystem === "writable") {
    issues.push({
      level,
      code: "scanner-repository-writable",
      message: "Scanner execution should mount repository source read-only; writable scratch space must be separate.",
    });
  }
}

/**
 * Validate operator-controlled GitHub App deployment settings before a hosted runtime starts.
 *
 * The result deliberately contains only categorical diagnostics. Secret values and filesystem
 * contents are never echoed into messages, making the result safe to surface in startup logs.
 * Scanner-isolation fields describe controls enforced by the surrounding container/sandbox runtime;
 * this preflight validates that contract and does not pretend Node child processes implement it.
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

  validateWebhookSecrets(config, issues);

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

  validateScannerIsolation(config, issues);

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
