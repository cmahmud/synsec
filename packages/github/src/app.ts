import { createHmac, sign as cryptoSign, timingSafeEqual } from "node:crypto";

const MAX_WEBHOOK_BYTES = 10 * 1024 * 1024;
const APP_JWT_LIFETIME_SECONDS = 9 * 60;

export interface GitHubAppTokenOptions {
  apiVersion?: string;
  userAgent?: string;
  fetch?: typeof globalThis.fetch;
}

export interface GitHubInstallationToken {
  token: string;
  expiresAt: string;
}

export interface GitHubAppWebhook {
  event: "pull_request" | "push" | "installation" | "installation_repositories";
  action?: string;
  deliveryId?: string;
  installationId?: number;
  repository?: string;
  headSha?: string;
  baseSha?: string;
  pullRequestNumber?: number;
}

function nonEmpty(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required.`);
  return normalized;
}

function positiveInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer.`);
  }
  return value;
}

function base64url(value: string | Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function rawBytes(body: string | Uint8Array): Buffer {
  const bytes = typeof body === "string" ? Buffer.from(body, "utf8") : Buffer.from(body);
  if (bytes.byteLength > MAX_WEBHOOK_BYTES) {
    throw new Error(`GitHub webhook body exceeds the ${MAX_WEBHOOK_BYTES}-byte limit.`);
  }
  return bytes;
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function integerValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : undefined;
}

function repositoryName(payload: Record<string, unknown>): string | undefined {
  const repository = objectValue(payload.repository);
  const fullName = stringValue(repository?.full_name);
  return fullName && /^[^/\s]+\/[^/\s]+$/.test(fullName) ? fullName : undefined;
}

/** Verify GitHub's X-Hub-Signature-256 against the exact request bytes. */
export function verifyGitHubWebhookSignature(
  body: string | Uint8Array,
  signatureHeader: string | undefined,
  webhookSecret: string,
): boolean {
  const secret = nonEmpty(webhookSecret, "GitHub webhook secret");
  const signature = signatureHeader?.trim();
  if (!signature || !/^sha256=[a-f0-9]{64}$/i.test(signature)) return false;

  const expected = createHmac("sha256", secret).update(rawBytes(body)).digest();
  const supplied = Buffer.from(signature.slice("sha256=".length), "hex");
  return supplied.byteLength === expected.byteLength && timingSafeEqual(supplied, expected);
}

/**
 * Verify and normalize only GitHub App events SynSec currently understands.
 * Scanner targets are never derived from arbitrary payload URLs.
 */
export function parseVerifiedGitHubAppWebhook(input: {
  body: string | Uint8Array;
  signatureHeader?: string;
  webhookSecret: string;
  eventName: string;
  deliveryId?: string;
}): GitHubAppWebhook {
  if (!verifyGitHubWebhookSignature(input.body, input.signatureHeader, input.webhookSecret)) {
    throw new Error("GitHub webhook signature verification failed.");
  }

  const eventName = nonEmpty(input.eventName, "GitHub event name");
  if (!["pull_request", "push", "installation", "installation_repositories"].includes(eventName)) {
    throw new Error(`Unsupported GitHub App event: ${eventName}`);
  }

  let payload: Record<string, unknown>;
  try {
    payload = objectValue(JSON.parse(rawBytes(input.body).toString("utf8"))) ?? (() => { throw new Error(); })();
  } catch {
    throw new Error("GitHub webhook body must be a JSON object.");
  }

  const installationId = integerValue(objectValue(payload.installation)?.id);
  const repository = repositoryName(payload);
  const action = stringValue(payload.action);
  const deliveryId = input.deliveryId?.trim() || undefined;

  if (eventName === "pull_request") {
    const pullRequest = objectValue(payload.pull_request);
    const headSha = stringValue(objectValue(pullRequest?.head)?.sha);
    const baseSha = stringValue(objectValue(pullRequest?.base)?.sha);
    const pullRequestNumber = integerValue(payload.number);
    if (!repository || !installationId || !headSha || !baseSha || !pullRequestNumber) {
      throw new Error("GitHub pull_request webhook is missing required repository, installation, PR, or commit identity.");
    }
    return {
      event: "pull_request",
      ...(action ? { action } : {}),
      ...(deliveryId ? { deliveryId } : {}),
      installationId,
      repository,
      headSha,
      baseSha,
      pullRequestNumber,
    };
  }

  if (eventName === "push") {
    const headSha = stringValue(payload.after);
    if (!repository || !installationId || !headSha) {
      throw new Error("GitHub push webhook is missing required repository, installation, or commit identity.");
    }
    return {
      event: "push",
      ...(deliveryId ? { deliveryId } : {}),
      installationId,
      repository,
      headSha,
    };
  }

  if (!installationId) throw new Error(`GitHub ${eventName} webhook is missing installation identity.`);
  return {
    event: eventName as "installation" | "installation_repositories",
    ...(action ? { action } : {}),
    ...(deliveryId ? { deliveryId } : {}),
    installationId,
    ...(repository ? { repository } : {}),
  };
}

/** Create a short-lived RS256 GitHub App JWT. */
export function createGitHubAppJwt(appId: string | number, privateKey: string, now = Date.now()): string {
  const issuer = String(appId).trim();
  if (!/^\d+$/.test(issuer) || issuer === "0") throw new Error("GitHub App id must be a positive integer.");
  const key = nonEmpty(privateKey, "GitHub App private key");
  if (!Number.isFinite(now) || now <= 0) throw new Error("JWT clock must be a positive timestamp.");

  const issuedAt = Math.floor(now / 1000) - 30;
  const expiresAt = issuedAt + APP_JWT_LIFETIME_SECONDS;
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64url(JSON.stringify({ iat: issuedAt, exp: expiresAt, iss: issuer }));
  const signingInput = `${header}.${payload}`;
  const signature = cryptoSign("RSA-SHA256", Buffer.from(signingInput), key);
  return `${signingInput}.${base64url(signature)}`;
}

/** Exchange an app JWT for one installation token using GitHub's fixed API host. */
export async function createGitHubInstallationToken(
  installationId: number,
  appJwt: string,
  options: GitHubAppTokenOptions = {},
): Promise<GitHubInstallationToken> {
  const id = positiveInteger(installationId, "GitHub installation id");
  const jwt = nonEmpty(appJwt, "GitHub App JWT");
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (!fetchImpl) throw new Error("No fetch implementation is available for GitHub App authentication.");

  const response = await fetchImpl(`https://api.github.com/app/installations/${id}/access_tokens`, {
    method: "POST",
    redirect: "error",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${jwt}`,
      "Content-Type": "application/json",
      "User-Agent": options.userAgent?.trim() || "synsec/0.2",
      "X-GitHub-Api-Version": options.apiVersion?.trim() || "2022-11-28",
    },
    body: "{}",
  });

  const text = await response.text();
  if (!response.ok) {
    const detail = text.replace(/[\r\n]+/g, " ").slice(0, 500).trim();
    throw new Error(`GitHub installation-token API returned HTTP ${response.status}${detail ? `: ${detail}` : "."}`);
  }

  let payload: Record<string, unknown>;
  try {
    payload = objectValue(text ? JSON.parse(text) : {}) ?? {};
  } catch {
    throw new Error("GitHub installation-token API returned invalid JSON.");
  }
  const token = stringValue(payload.token);
  const expiresAt = stringValue(payload.expires_at);
  if (!token || !expiresAt) throw new Error("GitHub installation-token API response is missing token metadata.");
  return { token, expiresAt };
}
