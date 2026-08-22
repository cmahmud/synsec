import { createHmac, sign as cryptoSign, timingSafeEqual } from "node:crypto";

const MAX_WEBHOOK_BYTES = 10 * 1024 * 1024;
const APP_JWT_LIFETIME_SECONDS = 9 * 60;
const MAX_WEBHOOK_SECRETS = 2;
const MAX_WEBHOOK_SECRET_BYTES = 4096;
const SCANNABLE_PULL_REQUEST_ACTIONS = new Set(["opened", "reopened", "synchronize", "ready_for_review"]);

export type GitHubWebhookSecret = string | readonly string[];

export interface GitHubAppTokenOptions {
  apiVersion?: string;
  userAgent?: string;
  fetch?: typeof globalThis.fetch;
}

export type GitHubInstallationPermissionLevel = "read" | "write";
export type GitHubInstallationPermissions = Record<string, GitHubInstallationPermissionLevel>;

export interface GitHubInstallationToken {
  token: string;
  expiresAt: string;
  permissions?: GitHubInstallationPermissions;
  repositorySelection?: "all" | "selected";
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

function webhookSecrets(value: GitHubWebhookSecret): string[] {
  const values = typeof value === "string" ? [value] : [...value];
  if (values.length < 1 || values.length > MAX_WEBHOOK_SECRETS) {
    throw new Error(`GitHub webhook secret set must contain between 1 and ${MAX_WEBHOOK_SECRETS} secrets.`);
  }
  const result = values.map((entry) => {
    const secret = nonEmpty(entry, "GitHub webhook secret");
    if (Buffer.byteLength(secret, "utf8") > MAX_WEBHOOK_SECRET_BYTES) {
      throw new Error(`GitHub webhook secret exceeds ${MAX_WEBHOOK_SECRET_BYTES} bytes.`);
    }
    return secret;
  });
  if (new Set(result).size !== result.length) {
    throw new Error("GitHub webhook secret set contains duplicates.");
  }
  return result;
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

function installationPermissions(value: unknown): GitHubInstallationPermissions | undefined {
  if (value === undefined) return undefined;
  const record = objectValue(value);
  if (!record) throw new Error("GitHub installation-token API returned invalid permission metadata.");
  const permissions: GitHubInstallationPermissions = {};
  for (const [name, level] of Object.entries(record)) {
    const normalizedName = name.trim();
    if (!normalizedName || normalizedName.length > 128 || !/^[a-z0-9_]+$/i.test(normalizedName)) {
      throw new Error("GitHub installation-token API returned invalid permission metadata.");
    }
    if (level !== "read" && level !== "write") {
      throw new Error("GitHub installation-token API returned invalid permission metadata.");
    }
    permissions[normalizedName] = level;
  }
  return permissions;
}

/** Verify GitHub's X-Hub-Signature-256 against one active secret or a bounded rotation pair. */
export function verifyGitHubWebhookSignature(
  body: string | Uint8Array,
  signatureHeader: string | undefined,
  webhookSecret: GitHubWebhookSecret,
): boolean {
  const secrets = webhookSecrets(webhookSecret);
  const signature = signatureHeader?.trim();
  if (!signature || !/^sha256=[a-f0-9]{64}$/i.test(signature)) return false;

  const bytes = rawBytes(body);
  const supplied = Buffer.from(signature.slice("sha256=".length), "hex");
  let matched = false;
  for (const secret of secrets) {
    const expected = createHmac("sha256", secret).update(bytes).digest();
    const equal = supplied.byteLength === expected.byteLength && timingSafeEqual(supplied, expected);
    matched = equal || matched;
  }
  return matched;
}

/**
 * Verify and normalize only GitHub App events SynSec currently understands.
 * Scanner targets are never derived from arbitrary payload URLs.
 */
export function parseVerifiedGitHubAppWebhook(input: {
  body: string | Uint8Array;
  signatureHeader?: string;
  webhookSecret: GitHubWebhookSecret;
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
    const parsed = objectValue(JSON.parse(rawBytes(input.body).toString("utf8")));
    if (!parsed) throw new Error();
    payload = parsed;
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

  if (!installationId || !action) {
    throw new Error("GitHub installation webhook is missing required installation identity or action.");
  }
  return {
    event: eventName,
    action,
    ...(deliveryId ? { deliveryId } : {}),
    installationId,
    ...(repository ? { repository } : {}),
  };
}

export function shouldScanGitHubAppWebhook(webhook: GitHubAppWebhook): boolean {
  if (webhook.event === "push") return true;
  return webhook.event === "pull_request" && Boolean(webhook.action && SCANNABLE_PULL_REQUEST_ACTIONS.has(webhook.action));
}

export function createGitHubAppJwt(
  appId: string | number,
  privateKey: string,
  nowSeconds = Math.floor(Date.now() / 1000),
): string {
  const issuer = nonEmpty(String(appId), "GitHub App id");
  if (!Number.isSafeInteger(nowSeconds) || nowSeconds <= 0) throw new Error("GitHub App JWT timestamp must be a positive integer.");
  const issuedAt = nowSeconds - 60;
  const expiresAt = issuedAt + APP_JWT_LIFETIME_SECONDS;
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64url(JSON.stringify({ iat: issuedAt, exp: expiresAt, iss: issuer }));
  const signingInput = `${header}.${payload}`;
  const signature = cryptoSign("RSA-SHA256", Buffer.from(signingInput), privateKey);
  return `${signingInput}.${base64url(signature)}`;
}

export async function createGitHubInstallationToken(
  appId: string | number,
  privateKey: string,
  installationId: number,
  options: GitHubAppTokenOptions = {},
): Promise<GitHubInstallationToken> {
  const id = positiveInteger(installationId, "GitHub installation id");
  const fetchImpl = options.fetch ?? globalThis.fetch;
  const response = await fetchImpl(`https://api.github.com/app/installations/${id}/access_tokens`, {
    method: "POST",
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${createGitHubAppJwt(appId, privateKey)}`,
      "x-github-api-version": options.apiVersion ?? "2022-11-28",
      "user-agent": options.userAgent ?? "synsec/0.2",
    },
  });
  if (!response.ok) {
    const detail = (await response.text()).replace(/[\r\n]+/g, " ").trim().slice(0, 500);
    throw new Error(`GitHub installation-token request failed (${response.status})${detail ? `: ${detail}` : "."}`);
  }
  const payload = await response.json() as Record<string, unknown>;
  const token = stringValue(payload.token);
  const expiresAt = stringValue(payload.expires_at);
  if (!token || !expiresAt || !Number.isFinite(Date.parse(expiresAt))) {
    throw new Error("GitHub installation-token API returned an invalid token response.");
  }
  const permissions = installationPermissions(payload.permissions);
  const repositorySelection = payload.repository_selection === "all" || payload.repository_selection === "selected"
    ? payload.repository_selection
    : undefined;
  return {
    token,
    expiresAt,
    ...(permissions ? { permissions } : {}),
    ...(repositorySelection ? { repositorySelection } : {}),
  };
}
