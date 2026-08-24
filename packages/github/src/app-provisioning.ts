import { randomBytes, timingSafeEqual } from "node:crypto";
import { buildSynSecGitHubAppSetupContract, type SynSecGitHubAppSetupOptions } from "./app-setup.js";

const MAX_URL_LENGTH = 2048;
const MAX_NAME_LENGTH = 100;
const MAX_DESCRIPTION_LENGTH = 255;
const MAX_ORGANIZATION_LENGTH = 39;
const MAX_STATE_LENGTH = 256;
const MAX_CODE_LENGTH = 512;

export interface SynSecGitHubAppManifestOptions extends SynSecGitHubAppSetupOptions {
  homepageUrl: string;
  webhookUrl: string;
  redirectUrl: string;
  setupUrl?: string;
  name?: string;
  description?: string;
  public?: boolean;
  setupOnUpdate?: boolean;
}

export interface SynSecGitHubAppManifest {
  name?: string;
  url: string;
  hook_attributes: {
    url: string;
    active: true;
  };
  redirect_url: string;
  setup_url?: string;
  setup_on_update?: boolean;
  public: boolean;
  default_permissions: Record<string, "read" | "write">;
  default_events: string[];
  description?: string;
}

export interface SynSecGitHubAppManifestRegistration {
  version: 1;
  method: "POST";
  action: string;
  fields: {
    manifest: string;
    state: string;
  };
  interpretation: "registration-request-not-provisioning-success";
}

export interface SynSecGitHubAppManifestCallback {
  version: 1;
  code: string;
  interpretation: "validated-callback-not-conversion-success";
}

function boundedSingleLine(value: string, label: string, maximum: number): string {
  if (typeof value !== "string") throw new Error(`${label} must be a string.`);
  const normalized = value.trim();
  if (!normalized || normalized.length > maximum || /[\u0000-\u001f\u007f]/.test(normalized)) {
    throw new Error(`${label} must be a bounded non-empty single-line value.`);
  }
  return normalized;
}

function httpsUrl(value: string, label: string): string {
  const normalized = boundedSingleLine(value, label, MAX_URL_LENGTH);
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error(`${label} must be an absolute HTTPS URL.`);
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash) {
    throw new Error(`${label} must be an absolute HTTPS URL without credentials or a fragment.`);
  }
  return parsed.toString();
}

function optionalText(value: string | undefined, label: string, maximum: number): string | undefined {
  return value === undefined ? undefined : boundedSingleLine(value, label, maximum);
}

function organization(value: string): string {
  const normalized = boundedSingleLine(value, "GitHub organization", MAX_ORGANIZATION_LENGTH);
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(normalized) || normalized.includes("--")) {
    throw new Error("GitHub organization is invalid.");
  }
  return normalized;
}

function stateToken(value: string): string {
  const normalized = boundedSingleLine(value, "GitHub App manifest state", MAX_STATE_LENGTH);
  if (!/^[A-Za-z0-9_-]+$/.test(normalized)) throw new Error("GitHub App manifest state contains unsupported characters.");
  return normalized;
}

function callbackCode(value: string): string {
  const normalized = boundedSingleLine(value, "GitHub App manifest callback code", MAX_CODE_LENGTH);
  if (!/^[A-Za-z0-9_-]+$/.test(normalized)) throw new Error("GitHub App manifest callback code contains unsupported characters.");
  return normalized;
}

function equalState(actual: string, expected: string): boolean {
  const actualBytes = Buffer.from(actual, "utf8");
  const expectedBytes = Buffer.from(expected, "utf8");
  if (actualBytes.length !== expectedBytes.length) return false;
  return timingSafeEqual(actualBytes, expectedBytes);
}

/**
 * Build the feature-aware GitHub App manifest used for initial registration.
 *
 * The output intentionally contains no webhook secret, private key, client secret, installation
 * token, or durable SynSec state. HTTPS is mandatory because these URLs become trust-boundary
 * redirects/webhook destinations in a production GitHub App registration.
 */
export function buildSynSecGitHubAppManifest(options: SynSecGitHubAppManifestOptions): SynSecGitHubAppManifest {
  const setup = buildSynSecGitHubAppSetupContract(options);
  const name = optionalText(options.name, "GitHub App name", MAX_NAME_LENGTH);
  const description = optionalText(options.description, "GitHub App description", MAX_DESCRIPTION_LENGTH);
  const setupUrl = options.setupUrl === undefined ? undefined : httpsUrl(options.setupUrl, "GitHub App setup URL");
  if (options.setupOnUpdate === true && !setupUrl) {
    throw new Error("GitHub App setupOnUpdate requires a setup URL.");
  }

  return {
    ...(name ? { name } : {}),
    url: httpsUrl(options.homepageUrl, "GitHub App homepage URL"),
    hook_attributes: {
      url: httpsUrl(options.webhookUrl, "GitHub App webhook URL"),
      active: true,
    },
    redirect_url: httpsUrl(options.redirectUrl, "GitHub App manifest redirect URL"),
    ...(setupUrl ? { setup_url: setupUrl } : {}),
    ...(setupUrl ? { setup_on_update: options.setupOnUpdate ?? true } : {}),
    public: options.public ?? false,
    default_permissions: { ...setup.permissions },
    default_events: [...setup.events],
    ...(description ? { description } : {}),
  };
}

/**
 * Build the exact POST target/fields for GitHub's App Manifest registration handshake.
 *
 * Callers must keep the returned state in a short-lived server-side session and submit these fields
 * as form data. This helper does not perform a browser redirect, persist state, or claim that an App
 * was created merely because a registration request was generated.
 */
export function createSynSecGitHubAppManifestRegistration(input: {
  manifest: SynSecGitHubAppManifest;
  organization?: string;
  state?: string;
}): SynSecGitHubAppManifestRegistration {
  const state = input.state === undefined ? randomBytes(32).toString("base64url") : stateToken(input.state);
  const action = input.organization
    ? `https://github.com/organizations/${encodeURIComponent(organization(input.organization))}/settings/apps/new`
    : "https://github.com/settings/apps/new";
  const serialized = JSON.stringify(input.manifest);
  if (Buffer.byteLength(serialized, "utf8") > 32 * 1024) throw new Error("GitHub App manifest exceeds 32 KiB.");

  return {
    version: 1,
    method: "POST",
    action,
    fields: { manifest: serialized, state },
    interpretation: "registration-request-not-provisioning-success",
  };
}

/**
 * Validate the redirect from GitHub before a caller exchanges the one-time manifest code.
 *
 * The code is credential-adjacent and deliberately returned only to the immediate caller; this
 * module never logs, persists, or serializes it into status/readiness output. Conversion to the App
 * id/private key/webhook secret remains a hosting/secret-manager boundary.
 */
export function validateSynSecGitHubAppManifestCallback(input: {
  code: string | undefined;
  state: string | undefined;
  expectedState: string;
}): SynSecGitHubAppManifestCallback {
  const expected = stateToken(input.expectedState);
  if (input.state === undefined || input.code === undefined) {
    throw new Error("GitHub App manifest callback is missing code or state.");
  }
  const actual = stateToken(input.state);
  if (!equalState(actual, expected)) throw new Error("GitHub App manifest callback state does not match.");

  return {
    version: 1,
    code: callbackCode(input.code),
    interpretation: "validated-callback-not-conversion-success",
  };
}
