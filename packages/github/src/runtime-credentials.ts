import type { GitHubWebhookSecret } from "./app.js";

export interface GitHubAppRuntimeCredentialSnapshot {
  generation: string;
  privateKey: string;
  webhookSecret: GitHubWebhookSecret;
}

export interface GitHubAppRuntimeCredentialStatus {
  version: 1;
  generation: string;
  webhookSecretCount: 1 | 2;
  reloadCount: number;
  interpretation: "memory-only-runtime-credential-generation";
}

export interface GitHubAppRuntimeCredentialSource {
  getPrivateKey(): string;
  getWebhookSecret(): GitHubWebhookSecret;
  getStatus(): GitHubAppRuntimeCredentialStatus;
  reload(load: () => Promise<GitHubAppRuntimeCredentialSnapshot>): Promise<GitHubAppRuntimeCredentialStatus>;
}

const MAX_PRIVATE_KEY_BYTES = 64 * 1024;
const MAX_WEBHOOK_SECRET_BYTES = 4096;
const MAX_GENERATION_LENGTH = 128;
const SAFE_GENERATION = /^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/;

function generation(value: unknown): string {
  if (typeof value !== "string") throw new Error("GitHub App credential generation must be a string.");
  const normalized = value.trim();
  if (!normalized || normalized.length > MAX_GENERATION_LENGTH || !SAFE_GENERATION.test(normalized)) {
    throw new Error("GitHub App credential generation must be a bounded non-secret identifier.");
  }
  return normalized;
}

function privateKey(value: unknown): string {
  if (typeof value !== "string" || !value.trim()) throw new Error("GitHub App private key is required.");
  if (Buffer.byteLength(value, "utf8") > MAX_PRIVATE_KEY_BYTES) {
    throw new Error(`GitHub App private key exceeds ${MAX_PRIVATE_KEY_BYTES} bytes.`);
  }
  const normalized = value.trim();
  const pkcs1 = normalized.startsWith("-----BEGIN RSA PRIVATE KEY-----")
    && normalized.endsWith("-----END RSA PRIVATE KEY-----");
  const pkcs8 = normalized.startsWith("-----BEGIN PRIVATE KEY-----")
    && normalized.endsWith("-----END PRIVATE KEY-----");
  if (!pkcs1 && !pkcs8) throw new Error("GitHub App private key must be PEM encoded.");
  return value;
}

function webhookSecret(value: GitHubWebhookSecret): GitHubWebhookSecret {
  const values = typeof value === "string" ? [value] : [...value];
  if (values.length < 1 || values.length > 2) {
    throw new Error("GitHub App webhook verification requires one secret or two secrets during rotation overlap.");
  }
  const normalized = values.map((secret) => {
    if (typeof secret !== "string") throw new Error("GitHub App webhook secret must be a string.");
    const bytes = Buffer.byteLength(secret, "utf8");
    if (bytes < 32 || bytes > MAX_WEBHOOK_SECRET_BYTES) {
      throw new Error(`GitHub App webhook secret must contain between 32 and ${MAX_WEBHOOK_SECRET_BYTES} bytes.`);
    }
    return secret;
  });
  if (new Set(normalized).size !== normalized.length) {
    throw new Error("GitHub App webhook rotation secrets must be distinct.");
  }
  return normalized.length === 1 ? normalized[0]! : [normalized[0]!, normalized[1]!] as const;
}

function validateSnapshot(value: GitHubAppRuntimeCredentialSnapshot): GitHubAppRuntimeCredentialSnapshot {
  if (!value || typeof value !== "object") throw new Error("GitHub App runtime credential snapshot is required.");
  return {
    generation: generation(value.generation),
    privateKey: privateKey(value.privateKey),
    webhookSecret: webhookSecret(value.webhookSecret),
  };
}

/**
 * Own one memory-only GitHub App credential generation and swap it atomically after validation.
 *
 * The loader callback is the integration boundary for a secret manager, mounted credential file,
 * supervisor IPC mechanism, or other operator-controlled source. SynSec never persists, serializes,
 * logs, or returns credential values from status APIs. Reloads are serialized; a loader/validation
 * failure leaves the previous generation active. The generation identifier is deployment metadata,
 * not a credential version attestation from GitHub or the external secret manager.
 */
export function createGitHubAppRuntimeCredentialSource(
  initial: GitHubAppRuntimeCredentialSnapshot,
): GitHubAppRuntimeCredentialSource {
  let active = validateSnapshot(initial);
  let reloadCount = 0;
  let reloadTail: Promise<void> = Promise.resolve();

  const status = (): GitHubAppRuntimeCredentialStatus => ({
    version: 1,
    generation: active.generation,
    webhookSecretCount: (typeof active.webhookSecret === "string" ? 1 : active.webhookSecret.length) as 1 | 2,
    reloadCount,
    interpretation: "memory-only-runtime-credential-generation",
  });

  return {
    getPrivateKey(): string {
      return active.privateKey;
    },
    getWebhookSecret(): GitHubWebhookSecret {
      return active.webhookSecret;
    },
    getStatus: status,
    async reload(load): Promise<GitHubAppRuntimeCredentialStatus> {
      if (typeof load !== "function") throw new Error("GitHub App credential reload loader is required.");
      let resolveTurn!: () => void;
      const previous = reloadTail;
      reloadTail = new Promise<void>((resolve) => { resolveTurn = resolve; });
      await previous;
      try {
        const candidate = validateSnapshot(await load());
        if (candidate.generation === active.generation) {
          throw new Error("GitHub App credential reload generation must differ from the active generation.");
        }
        active = candidate;
        reloadCount += 1;
        return status();
      } finally {
        resolveTurn();
      }
    },
  };
}
