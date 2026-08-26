import type { IncomingMessage, ServerResponse } from "node:http";
import type { GitHubAppRuntimeCredentialStatus } from "./runtime-credentials.js";

const DEFAULT_PATH = "/_synsec/operator/status";
const MAX_PATH_LENGTH = 128;
const MAX_IDENTIFIER_LENGTH = 128;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/+\-]*$/;
const MAX_COUNTER = 1_000_000_000;

export type GitHubAppOperatorRecoveryPhase = "idle" | "isolated" | "recovering" | "ready" | "failed";
export type GitHubAppOperatorAdmissionState = "open" | "closed";

export interface GitHubAppOperatorStatusObservation {
  releaseId: string;
  schemaVersion: number;
  ready: boolean;
  credentialStatus: GitHubAppRuntimeCredentialStatus;
  webhookAdmission: GitHubAppOperatorAdmissionState;
  workerAdmission: GitHubAppOperatorAdmissionState;
  activeWebhookRequests: number;
  activeWorkerRuns: number;
  durableActiveLeases: number;
  recoveryPhase: GitHubAppOperatorRecoveryPhase;
  observedAt: string | Date;
}

export interface GitHubAppOperatorStatusSnapshot {
  version: 1;
  release: { id: string; schemaVersion: number };
  ready: boolean;
  credentials: {
    generation: string;
    webhookSecretCount: 1 | 2;
    reloadCount: number;
  };
  admission: {
    webhook: GitHubAppOperatorAdmissionState;
    worker: GitHubAppOperatorAdmissionState;
    activeWebhookRequests: number;
    activeWorkerRuns: number;
  };
  durable: { activeLeases: number };
  recovery: { phase: GitHubAppOperatorRecoveryPhase };
  observedAt: string;
  interpretation: "aggregate-operator-observation-not-external-security-proof";
}

export interface GitHubAppOperatorStatusHttpOptions {
  path?: string;
  /** Trusted hosting authentication/authorization boundary. False and thrown errors fail closed. */
  authorize(request: IncomingMessage): boolean | Promise<boolean>;
  /** Collect only the bounded observation contract below. Do not pass arbitrary backend payloads. */
  observe(): GitHubAppOperatorStatusObservation | Promise<GitHubAppOperatorStatusObservation>;
  /** Receives categorical errors only; original backend/authentication errors are discarded. */
  onError?: (error: Error) => void;
}

function boundedIdentifier(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} must be a string.`);
  const normalized = value.trim();
  if (!normalized || normalized.length > MAX_IDENTIFIER_LENGTH || !SAFE_IDENTIFIER.test(normalized)) {
    throw new Error(`${label} must be a bounded non-secret identifier.`);
  }
  return normalized;
}

function boundedCounter(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > MAX_COUNTER) {
    throw new Error(`${label} must be an integer between 0 and ${MAX_COUNTER}.`);
  }
  return value;
}

function positiveVersion(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > Number.MAX_SAFE_INTEGER) {
    throw new Error("GitHub App operator schema version must be a positive safe integer.");
  }
  return value;
}

function admission(value: unknown, label: string): GitHubAppOperatorAdmissionState {
  if (value !== "open" && value !== "closed") throw new Error(`${label} must be open or closed.`);
  return value;
}

function recoveryPhase(value: unknown): GitHubAppOperatorRecoveryPhase {
  if (value !== "idle" && value !== "isolated" && value !== "recovering" && value !== "ready" && value !== "failed") {
    throw new Error("GitHub App operator recovery phase is invalid.");
  }
  return value;
}

function timestamp(value: unknown): string {
  const date = value instanceof Date ? value : typeof value === "string" ? new Date(value) : undefined;
  if (!date || !Number.isFinite(date.getTime())) throw new Error("GitHub App operator observedAt must be a valid timestamp.");
  return date.toISOString();
}

function credentialStatus(value: GitHubAppRuntimeCredentialStatus): GitHubAppOperatorStatusSnapshot["credentials"] {
  if (!value || value.version !== 1 || value.interpretation !== "memory-only-runtime-credential-generation") {
    throw new Error("GitHub App operator credential status is invalid.");
  }
  if (value.webhookSecretCount !== 1 && value.webhookSecretCount !== 2) {
    throw new Error("GitHub App operator webhook secret count is invalid.");
  }
  return {
    generation: boundedIdentifier(value.generation, "GitHub App credential generation"),
    webhookSecretCount: value.webhookSecretCount,
    reloadCount: boundedCounter(value.reloadCount, "GitHub App credential reload count"),
  };
}

/**
 * Convert trusted operational observations into a fixed, aggregate-only snapshot.
 *
 * The function reconstructs every field instead of spreading caller objects, so backend errors,
 * tenant metadata, filesystem paths, tokens, keys, scanner output, and other untrusted properties
 * cannot accidentally cross this disclosure boundary. The resulting status is operator evidence
 * only: it does not prove GitHub credential acceptance, repository authorization, runtime safety,
 * fleet-wide health, exploitability, or absence of vulnerabilities.
 */
export function buildGitHubAppOperatorStatusSnapshot(
  observation: GitHubAppOperatorStatusObservation,
): GitHubAppOperatorStatusSnapshot {
  if (!observation || typeof observation !== "object") throw new Error("GitHub App operator observation is required.");
  if (typeof observation.ready !== "boolean") throw new Error("GitHub App operator readiness must be boolean.");
  return {
    version: 1,
    release: {
      id: boundedIdentifier(observation.releaseId, "GitHub App release id"),
      schemaVersion: positiveVersion(observation.schemaVersion),
    },
    ready: observation.ready,
    credentials: credentialStatus(observation.credentialStatus),
    admission: {
      webhook: admission(observation.webhookAdmission, "GitHub App webhook admission"),
      worker: admission(observation.workerAdmission, "GitHub App worker admission"),
      activeWebhookRequests: boundedCounter(observation.activeWebhookRequests, "GitHub App active webhook request count"),
      activeWorkerRuns: boundedCounter(observation.activeWorkerRuns, "GitHub App active worker run count"),
    },
    durable: {
      activeLeases: boundedCounter(observation.durableActiveLeases, "GitHub App durable active lease count"),
    },
    recovery: { phase: recoveryPhase(observation.recoveryPhase) },
    observedAt: timestamp(observation.observedAt),
    interpretation: "aggregate-operator-observation-not-external-security-proof",
  };
}

function statusPath(value: string | undefined): string {
  const path = value?.trim() || DEFAULT_PATH;
  if (!path.startsWith("/") || path.length > MAX_PATH_LENGTH || path.includes("?") || path.includes("#") || /[\u0000-\u001f\u007f]/.test(path)) {
    throw new Error("GitHub App operator status path must be a bounded absolute path without query or fragment components.");
  }
  return path;
}

function sendJson(response: ServerResponse, statusCode: number, payload: Record<string, unknown>): void {
  const body = `${JSON.stringify(payload)}\n`;
  response.statusCode = statusCode;
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.setHeader("content-length", Buffer.byteLength(body));
  response.setHeader("cache-control", "no-store");
  response.setHeader("x-content-type-options", "nosniff");
  response.end(body);
}

function categoricalError(options: GitHubAppOperatorStatusHttpOptions, code: "authorization_failed" | "observation_failed"): void {
  try {
    options.onError?.(new Error(`GitHub App operator status ${code}.`));
  } catch {
    // Logging/telemetry callbacks are outside the response trust boundary.
  }
}

/**
 * Create a framework-free protected operator-status endpoint.
 *
 * Authorization is caller-owned because SynSec cannot infer the deployment's operator identity
 * system. Unauthorized requests and authorization failures both receive 404 so the endpoint does
 * not disclose its presence. Observation failures return a categorical 503. Original errors are
 * never reflected to either HTTP clients or the optional callback.
 */
export function createGitHubAppOperatorStatusHttpHandler(options: GitHubAppOperatorStatusHttpOptions) {
  if (!options || typeof options.authorize !== "function" || typeof options.observe !== "function") {
    throw new Error("GitHub App operator status requires authorize and observe callbacks.");
  }
  const path = statusPath(options.path);

  return async function githubAppOperatorStatusHttpHandler(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    const requestPath = (request.url ?? "").split("?", 1)[0];
    if (requestPath !== path) {
      sendJson(response, 404, { status: "not_found" });
      return;
    }
    if (request.method !== "GET") {
      response.setHeader("allow", "GET");
      sendJson(response, 405, { status: "method_not_allowed" });
      return;
    }

    let authorized = false;
    try {
      authorized = (await options.authorize(request)) === true;
    } catch {
      categoricalError(options, "authorization_failed");
    }
    if (!authorized) {
      sendJson(response, 404, { status: "not_found" });
      return;
    }

    try {
      const snapshot = buildGitHubAppOperatorStatusSnapshot(await options.observe());
      sendJson(response, 200, snapshot as unknown as Record<string, unknown>);
    } catch {
      categoricalError(options, "observation_failed");
      sendJson(response, 503, { status: "unavailable" });
    }
  };
}
