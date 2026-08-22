import {
  createGitHubAppJwt,
  createGitHubInstallationToken,
  type GitHubAppTokenOptions,
  type GitHubInstallationToken,
} from "./app.js";

const DEFAULT_MIN_REMAINING_MS = 30_000;
const MAX_PRIVATE_KEY_BYTES = 64 * 1024;

export interface GitHubAppInstallationTokenProviderOptions extends GitHubAppTokenOptions {
  appId: string | number;
  privateKey: string;
  minRemainingMs?: number;
  now?: () => number;
  exchange?: typeof createGitHubInstallationToken;
}

function boundedPrivateKey(value: string): string {
  if (!value.trim()) throw new Error("GitHub App private key is required.");
  if (Buffer.byteLength(value, "utf8") > MAX_PRIVATE_KEY_BYTES) {
    throw new Error(`GitHub App private key exceeds ${MAX_PRIVATE_KEY_BYTES} bytes.`);
  }
  return value;
}

function minRemainingMs(value: number | undefined): number {
  const normalized = value ?? DEFAULT_MIN_REMAINING_MS;
  if (!Number.isSafeInteger(normalized) || normalized < 0 || normalized > 10 * 60 * 1000) {
    throw new Error("GitHub installation-token minimum remaining lifetime must be between 0 and 600000 milliseconds.");
  }
  return normalized;
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

/**
 * Build a memory-only installation-token provider for hosted App workers.
 *
 * A fresh short-lived App JWT is signed for every operation and immediately exchanged through the
 * fixed GitHub installation-token endpoint. Installation tokens are returned to the caller only;
 * this provider deliberately has no token cache, disk persistence, scanner integration, or logging.
 */
export function createGitHubAppInstallationTokenProvider(
  options: GitHubAppInstallationTokenProviderOptions,
): (installationId: number) => Promise<string> {
  const privateKey = boundedPrivateKey(options.privateKey);
  const minimum = minRemainingMs(options.minRemainingMs);
  const now = options.now ?? Date.now;
  const exchange = options.exchange ?? createGitHubInstallationToken;

  return async (installationId: number): Promise<string> => {
    const currentTime = now();
    if (!Number.isFinite(currentTime) || currentTime <= 0) {
      throw new Error("GitHub App token-provider clock must be a positive timestamp.");
    }
    const appJwt = createGitHubAppJwt(options.appId, privateKey, currentTime);
    const token = await exchange(installationId, appJwt, {
      apiVersion: options.apiVersion,
      userAgent: options.userAgent,
      fetch: options.fetch,
    });
    validateTokenLifetime(token, currentTime, minimum);
    return token.token;
  };
}
