import { isAbsolute, relative, resolve } from "node:path";

const MAX_IDENTIFIER_LENGTH = 128;
const MAX_ENVIRONMENT_NAME_LENGTH = 64;
const MAX_COMMAND_LENGTH = 256;
const MAX_IMAGE_LENGTH = 512;
const MAX_REPLICA_COUNT = 1000;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/+\-]*$/;
const SAFE_ENVIRONMENT_NAME = /^[A-Z][A-Z0-9_]*$/;
const ALLOWED_KEYS = new Set([
  "releaseId",
  "replicaId",
  "replicaCount",
  "appId",
  "credentialDirectory",
  "postgresUrlEnvironment",
  "listenHost",
  "port",
  "tlsMode",
  "workspaceDirectory",
  "scannerRuntimeCommand",
  "scannerImage",
  "operatorStatusPath",
]);

export interface GitHubAppHostProfile {
  releaseId: string;
  replicaId: string;
  replicaCount: number;
  appId: number;
  credentialDirectory: string;
  postgresUrlEnvironment: string;
  listenHost: string;
  port: number;
  tlsMode: "local" | "terminated-upstream";
  workspaceDirectory: string;
  scannerRuntimeCommand: string;
  scannerImage: string;
  operatorStatusPath: string;
}

export interface NormalizedGitHubAppHostProfile extends GitHubAppHostProfile {
  version: 1;
  interpretation: "secret-free-host-wiring-contract-not-runtime-readiness";
}

function identifier(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} must be a string.`);
  const normalized = value.trim();
  if (!normalized || normalized.length > MAX_IDENTIFIER_LENGTH || !SAFE_IDENTIFIER.test(normalized)) {
    throw new Error(`${label} must be a bounded non-secret identifier.`);
  }
  return normalized;
}

function positiveInteger(value: unknown, label: string, maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new Error(`${label} must be an integer between 1 and ${maximum}.`);
  }
  return value;
}

function absoluteDirectory(value: unknown, label: string): string {
  if (typeof value !== "string" || !isAbsolute(value) || value.includes("\0")) {
    throw new Error(`${label} must be an absolute path.`);
  }
  return resolve(value);
}

function pathsOverlap(left: string, right: string): boolean {
  if (left === right) return true;
  const child = (from: string, to: string): boolean => {
    const value = relative(from, to);
    return Boolean(value) && !value.startsWith("..") && !isAbsolute(value);
  };
  return child(left, right) || child(right, left);
}

function environmentName(value: unknown): string {
  if (typeof value !== "string") throw new Error("PostgreSQL URL environment reference must be a string.");
  const normalized = value.trim();
  if (!normalized || normalized.length > MAX_ENVIRONMENT_NAME_LENGTH || !SAFE_ENVIRONMENT_NAME.test(normalized)) {
    throw new Error("PostgreSQL URL environment reference must be a bounded environment-variable name, not a connection string.");
  }
  return normalized;
}

function listenHost(value: unknown): string {
  if (typeof value !== "string") throw new Error("GitHub App host listener must be a string.");
  const normalized = value.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (!normalized || normalized === "*" || normalized.length > 255 || /[\s/?#\u0000-\u001f\u007f]/.test(normalized)) {
    throw new Error("GitHub App host listener must be a bounded host name or IP address.");
  }
  return normalized;
}

function runtimeCommand(value: unknown): string {
  if (typeof value !== "string") throw new Error("Scanner runtime command must be a string.");
  const normalized = value.trim();
  if (!normalized || normalized.length > MAX_COMMAND_LENGTH || /[\s\u0000-\u001f\u007f]/.test(normalized)) {
    throw new Error("Scanner runtime command must be one bounded command token.");
  }
  return normalized;
}

function immutableImage(value: unknown): string {
  if (typeof value !== "string") throw new Error("Scanner image must be a string.");
  const normalized = value.trim();
  if (!normalized || normalized.length > MAX_IMAGE_LENGTH || /[\s\u0000-\u001f\u007f]/.test(normalized) || !/@sha256:[a-f0-9]{64}$/i.test(normalized)) {
    throw new Error("Scanner image must be a bounded immutable sha256 digest reference.");
  }
  return normalized;
}

function statusPath(value: unknown): string {
  if (typeof value !== "string") throw new Error("Operator status path must be a string.");
  const normalized = value.trim();
  if (!normalized.startsWith("/") || normalized.length > 128 || normalized.includes("?") || normalized.includes("#") || /[\u0000-\u001f\u007f]/.test(normalized)) {
    throw new Error("Operator status path must be a bounded absolute path.");
  }
  return normalized;
}

/**
 * Validate the non-secret wiring that hosting code may load from a declarative JSON file.
 *
 * The object is exact-keyed: unknown keys fail closed so fields such as privateKey, webhookSecret,
 * databaseUrl, tokens, or arbitrary metadata cannot silently become part of the deployment profile.
 * Actual credential files and the PostgreSQL connection value remain outside this object and must be
 * resolved by the trusted host from the mounted-credential and environment/secret-manager boundaries.
 */
export function parseGitHubAppHostProfile(value: unknown): NormalizedGitHubAppHostProfile {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("GitHub App host profile must be an object.");
  const object = value as Record<string, unknown>;
  if (Object.keys(object).some((key) => !ALLOWED_KEYS.has(key)) || Object.keys(object).length !== ALLOWED_KEYS.size) {
    throw new Error("GitHub App host profile must contain exactly the supported non-secret fields.");
  }

  const credentialDirectory = absoluteDirectory(object.credentialDirectory, "GitHub App credential directory");
  const workspaceDirectory = absoluteDirectory(object.workspaceDirectory, "GitHub App workspace directory");
  if (pathsOverlap(credentialDirectory, workspaceDirectory)) {
    throw new Error("GitHub App credential and repository workspace directories must be separate, non-nested trees.");
  }
  if (object.tlsMode !== "local" && object.tlsMode !== "terminated-upstream") {
    throw new Error("GitHub App production host TLS mode must be local or terminated-upstream.");
  }

  return {
    version: 1,
    releaseId: identifier(object.releaseId, "GitHub App release id"),
    replicaId: identifier(object.replicaId, "GitHub App replica id"),
    replicaCount: positiveInteger(object.replicaCount, "GitHub App replica count", MAX_REPLICA_COUNT),
    appId: positiveInteger(object.appId, "GitHub App id", Number.MAX_SAFE_INTEGER),
    credentialDirectory,
    postgresUrlEnvironment: environmentName(object.postgresUrlEnvironment),
    listenHost: listenHost(object.listenHost),
    port: positiveInteger(object.port, "GitHub App listener port", 65535),
    tlsMode: object.tlsMode,
    workspaceDirectory,
    scannerRuntimeCommand: runtimeCommand(object.scannerRuntimeCommand),
    scannerImage: immutableImage(object.scannerImage),
    operatorStatusPath: statusPath(object.operatorStatusPath),
    interpretation: "secret-free-host-wiring-contract-not-runtime-readiness",
  };
}
