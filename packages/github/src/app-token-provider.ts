import { sanitizeOperationalText } from "@synsec/scanner-sdk";
import {
  createGitHubAppJwt,
  createGitHubInstallationToken,
  type GitHubAppTokenOptions,
  type GitHubInstallationPermissionLevel,
  type GitHubInstallationToken,
} from "./app.js";

const DEFAULT_MIN_REMAINING_MS = 30_000;
const MAX_PRIVATE_KEY_BYTES = 64 * 1024;
const MAX_PERMISSION_REQUIREMENTS = 32;

export type GitHubPermissionRequirementsByPurpose = Record<
  string,
  Record<string, GitHubInstallationPermissionLevel>
>;

export interface GitHubAppInstallationTokenProviderOptions extends GitHubAppTokenOptions {
  appId: string | number;
  /** Static key or memory-only supplier resolved immediately before each JWT signature. */
  privateKey: string | (() => string);
  minRemainingMs?: number;
  now?: () => number;
  exchange?: typeof createGitHubInstallationToken;
  requiredPermissionsByPurpose?: GitHubPermissionRequirementsByPurpose;
}

function boundedPrivateKey(value: string): string {
  if (!value.trim()) throw new Error("GitHub App private key is required.");
  if (Buffer.byteLength(value, "utf8") > MAX_PRIVATE_KEY_BYTES) {
    throw new Error(`GitHub App private key exceeds ${MAX_PRIVATE_KEY_BYTES} bytes.`);
  }
  return value;
}

function privateKeySupplier(value: string | (() => string)): () => string {
  if (typeof value === "string") {
    const fixed = boundedPrivateKey(value);
    return () => fixed;
  }
  if (typeof value !== "function") throw new Error("GitHub App private key or supplier is required.");
  return () => boundedPrivateKey(value());
}

function minRemainingMs(value: number | undefined): number {
  const normalized = value ?? DEFAULT_MIN_REMAINING_MS;
  if (!Number.isSafeInteger(normalized) || normalized < 0 || normalized > 10 * 60 * 1000) {
    throw new Error("GitHub installation-token minimum remaining lifetime must be between 0 and 600000 milliseconds.");
  }
  return normalized;
}

function validateRequirements(value: GitHubPermissionRequirementsByPurpose | undefined): GitHubPermissionRequirementsByPurpose {
  if (!value) return {};
  const result: GitHubPermissionRequirementsByPurpose = {};
  let count = 0;
  for (const [purpose, permissions] of Object.entries(value)) {
    const normalizedPurpose = purpose.trim();
    if (!normalizedPurpose || normalizedPurpose.length > 64) {
      throw new Error("GitHub token permission purpose is invalid.");
    }
    const normalized: Record<string, GitHubInstallationPermissionLevel> = {};
    for (const [name, level] of Object.entries(permissions)) {
      count += 1;
      if (count > MAX_PERMISSION_REQUIREMENTS) {
        throw new Error(`GitHub token provider exceeds ${MAX_PERMISSION_REQUIREMENTS} permission requirements.`);
      }
      const permission = name.trim();
      if (!permission || permission.length > 128 || !/^[a-z0-9_]+$/i.test(permission)) {
        throw new Error("GitHub token permission requirement contains an invalid permission name.");
      }
      if (level !== "read" && level !== "write") {
        throw new Error("GitHub token permission requirement must be read or write.");
      }
      normalized[permission] = level;
    }
    result[normalizedPurpose] = normalized;
  }
  return result;
}

function validateTokenLifetime(token: GitHubInstallationToken, now: number, minimum: number): void {
  const expiresAt = Date.parse(token.expiresAt);
  if (!Number.isFinite(expiresAt)) {
    throw new Error("GitHub installation-token API returned an invalid expiration timestamp.");
  }
  if (expiresAt - now < minimum) {
    throw new Error("GitHub installation token expires too soon for a repository operation.");
  }
}

function permissionSatisfies(
  actual: GitHubInstallationPermissionLevel | undefined,
  required: GitHubInstallationPermissionLevel,
): boolean {
  if (required === "read") return actual === "read" || actual === "write";
  return actual === "write";
}

function validateTokenPermissions(
  token: GitHubInstallationToken,
  requirements: Record<string, GitHubInstallationPermissionLevel> | undefined,
  purpose: string | undefined,
): void {
  if (!requirements || Object.keys(requirements).length === 0) return;
  if (!token.permissions) {
    throw new Error(`GitHub installation token is missing permission metadata required for ${purpose ?? "this operation"}.`);
  }
  const missing = Object.entries(requirements)
    .filter(([name, required]) => !permissionSatisfies(token.permissions?.[name], required))
    .map(([name, required]) => `${name}:${required}`)
    .sort();
  if (missing.length > 0) {
    throw new Error(`GitHub installation token lacks required permission(s) for ${purpose ?? "this operation"}: ${missing.join(", ")}.`);
  }
}

function safeExchangeError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return sanitizeOperationalText(message, 1000) || "GitHub installation-token exchange failed.";
}

/**
 * Build a memory-only installation-token provider for hosted App workers.
 *
 * A fresh short-lived App JWT is signed for every operation and immediately exchanged through the
 * fixed GitHub installation-token endpoint. The private key may be supplied dynamically; when a
 * supplier is used it is resolved and bounded immediately before each signature so a validated
 * in-memory credential controller can atomically rotate keys without rebuilding the worker. A
 * supplier failure aborts the operation rather than falling back to an old or empty key.
 * Installation tokens are returned to the caller only; this provider deliberately has no token
 * cache, disk persistence, scanner integration, or logging. Optional purpose-specific permission
 * requirements are checked against GitHub's token metadata before the credential is returned to
 * acquisition/publication code. Transport/exchange failures are sanitized before propagation so
 * authorization headers, tokens, or credential-bearing proxy URLs cannot leak into caller logging.
 */
export function createGitHubAppInstallationTokenProvider(
  options: GitHubAppInstallationTokenProviderOptions,
): (installationId: number, purpose?: string) => Promise<string> {
  const getPrivateKey = privateKeySupplier(options.privateKey);
  const minimum = minRemainingMs(options.minRemainingMs);
  const requirements = validateRequirements(options.requiredPermissionsByPurpose);
  const now = options.now ?? Date.now;
  const exchange = options.exchange ?? createGitHubInstallationToken;

  return async (installationId: number, purpose?: string): Promise<string> => {
    const currentTime = now();
    if (!Number.isFinite(currentTime) || currentTime <= 0) {
      throw new Error("GitHub App token-provider clock must be a positive timestamp.");
    }
    const appJwt = createGitHubAppJwt(options.appId, getPrivateKey(), currentTime);
    let token: GitHubInstallationToken;
    try {
      token = await exchange(installationId, appJwt, {
        apiVersion: options.apiVersion,
        userAgent: options.userAgent,
        fetch: options.fetch,
      });
    } catch (error) {
      throw new Error(safeExchangeError(error));
    }
    validateTokenLifetime(token, currentTime, minimum);
    validateTokenPermissions(token, purpose ? requirements[purpose] : undefined, purpose);
    return token.token;
  };
}
