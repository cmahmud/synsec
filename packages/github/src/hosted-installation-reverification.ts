import type {
  SynSecAccessibleGitHubInstallation,
  SynSecGitHubUserInstallationTransport,
  SynSecHostedGitHubPrincipal,
} from "./hosted-installation-ownership.js";

const MAX_IDENTIFIER_LENGTH = 128;
const MIN_FRESHNESS_MS = 60_000;
const MAX_FRESHNESS_MS = 30 * 24 * 60 * 60 * 1000;

export type SynSecHostedInstallationRevocationReason =
  | "inaccessible"
  | "suspended"
  | "account-identity-changed";

export interface SynSecHostedInstallationReverificationFence {
  epoch: number;
  tenantId: string;
  installationId: number;
  githubUserId: number;
  accountId: number;
  accountType: "User" | "Organization";
}

export type SynSecHostedInstallationReverificationFinishResult = "applied" | "stale" | "conflict";

export interface SynSecHostedInstallationReverificationStore {
  /**
   * Allocate a monotonically increasing durable epoch for the exact current tenant/user proof.
   * Returns undefined when the tenant, installation, or proof user does not match durable ownership.
   */
  beginReverification(
    tenantId: string,
    installationId: number,
    githubUserId: number,
  ): Promise<SynSecHostedInstallationReverificationFence | undefined>;
  /** Apply a successful GitHub observation only if this epoch is still current. */
  finishVerified(input: SynSecHostedInstallationReverificationFence & {
    accountLogin: string;
  }): Promise<SynSecHostedInstallationReverificationFinishResult>;
  /** Apply a definitive negative GitHub observation only if this epoch is still current. */
  finishRevoked(input: SynSecHostedInstallationReverificationFence & {
    reason: SynSecHostedInstallationRevocationReason;
  }): Promise<SynSecHostedInstallationReverificationFinishResult>;
  /**
   * Durable authorization gate. Implementations must require active state and a successful
   * verification no older than maxAgeMs using backend time rather than a caller clock.
   */
  isFreshlyAuthorized(tenantId: string, installationId: number, maxAgeMs: number): Promise<boolean>;
}

export interface SynSecHostedInstallationReverificationEvidence {
  status: "verified" | "revoked" | "superseded";
  tenantId: string;
  installationId: number;
  epoch: number;
  reason?: SynSecHostedInstallationRevocationReason;
  interpretation: "fresh-user-access-and-fenced-durable-reverification-only";
}

function boundedIdentifier(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} must be a string.`);
  const normalized = value.trim();
  if (!normalized || normalized.length > MAX_IDENTIFIER_LENGTH || !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(normalized)) {
    throw new Error(`${label} must be a bounded non-secret identifier.`);
  }
  return normalized;
}

function positiveInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer.`);
  }
  return value;
}

function accountLogin(value: unknown): string {
  if (typeof value !== "string") throw new Error("GitHub account login must be a string.");
  const normalized = value.trim();
  if (!normalized || normalized.length > 255 || /[\u0000-\u001f\u007f]/.test(normalized)) {
    throw new Error("GitHub account login is invalid.");
  }
  return normalized;
}

function definitiveInstallation(
  value: SynSecAccessibleGitHubInstallation | undefined,
  expectedId: number,
): { status: "verified"; value: SynSecAccessibleGitHubInstallation } | { status: "revoked"; reason: SynSecHostedInstallationRevocationReason } {
  if (value === undefined) return { status: "revoked", reason: "inaccessible" };
  if (!value || typeof value !== "object") throw new Error("GitHub installation response is invalid.");
  if (positiveInteger(value.id, "GitHub installation id") !== expectedId) {
    throw new Error("GitHub installation lookup returned an unexpected installation.");
  }
  if (!value.account || typeof value.account !== "object") throw new Error("GitHub installation account is invalid.");
  positiveInteger(value.account.id, "GitHub installation account id");
  accountLogin(value.account.login);
  if (value.account.type !== "User" && value.account.type !== "Organization") {
    throw new Error("GitHub installation account type is invalid.");
  }
  if (value.repositorySelection !== "all" && value.repositorySelection !== "selected") {
    throw new Error("GitHub installation repository selection is invalid.");
  }
  if (value.suspendedAt !== undefined) {
    if (typeof value.suspendedAt !== "string" || !Number.isFinite(Date.parse(value.suspendedAt))) {
      throw new Error("GitHub installation suspension state is invalid.");
    }
    return { status: "revoked", reason: "suspended" };
  }
  return { status: "verified", value };
}

function finishEvidence(
  result: SynSecHostedInstallationReverificationFinishResult,
  fence: SynSecHostedInstallationReverificationFence,
  reason?: SynSecHostedInstallationRevocationReason,
): SynSecHostedInstallationReverificationEvidence {
  if (result === "conflict") throw new Error("Hosted installation ownership changed during re-verification.");
  if (result === "stale") {
    return {
      status: "superseded",
      tenantId: fence.tenantId,
      installationId: fence.installationId,
      epoch: fence.epoch,
      interpretation: "fresh-user-access-and-fenced-durable-reverification-only",
    };
  }
  if (result !== "applied") throw new Error("Hosted installation re-verification store returned an invalid result.");
  return {
    status: reason ? "revoked" : "verified",
    tenantId: fence.tenantId,
    installationId: fence.installationId,
    epoch: fence.epoch,
    ...(reason ? { reason } : {}),
    interpretation: "fresh-user-access-and-fenced-durable-reverification-only",
  };
}

/**
 * Re-check the user proof behind a durable hosted installation claim.
 *
 * beginReverification() allocates a durable epoch before the remote calls. A later replica can
 * therefore supersede an earlier in-flight check, and the stale result cannot overwrite newer
 * authorization state. Transport failures do not become revocation evidence; callers should rely on
 * the durable freshness gate to fail closed when successful verification evidence ages out.
 */
export async function reverifySynSecHostedGitHubInstallation(options: {
  principal: SynSecHostedGitHubPrincipal;
  installationId: number;
  transport: SynSecGitHubUserInstallationTransport;
  store: SynSecHostedInstallationReverificationStore;
}): Promise<SynSecHostedInstallationReverificationEvidence> {
  if (!options || typeof options !== "object") throw new Error("Hosted GitHub installation re-verification options are required.");
  boundedIdentifier(options.principal?.subject, "Hosted principal subject");
  const tenantId = boundedIdentifier(options.principal?.tenantId, "Hosted tenant id");
  const githubUserId = positiveInteger(options.principal?.githubUserId, "Authenticated GitHub user id");
  const installationId = positiveInteger(options.installationId, "GitHub installation id");
  if (!options.transport || typeof options.transport.getAuthenticatedUser !== "function" || typeof options.transport.getAccessibleInstallation !== "function") {
    throw new Error("User-scoped GitHub installation transport is required.");
  }
  if (!options.store
    || typeof options.store.beginReverification !== "function"
    || typeof options.store.finishVerified !== "function"
    || typeof options.store.finishRevoked !== "function") {
    throw new Error("Hosted installation re-verification store is required.");
  }

  let fence: SynSecHostedInstallationReverificationFence | undefined;
  try {
    fence = await options.store.beginReverification(tenantId, installationId, githubUserId);
  } catch {
    throw new Error("Hosted installation re-verification persistence failed.");
  }
  if (!fence) throw new Error("Hosted installation ownership proof does not match the authenticated tenant and GitHub user.");

  let authenticatedUser: { id: number; login: string };
  let accessible: SynSecAccessibleGitHubInstallation | undefined;
  try {
    authenticatedUser = await options.transport.getAuthenticatedUser();
    const returnedUserId = positiveInteger(authenticatedUser?.id, "GitHub authenticated user id");
    accountLogin(authenticatedUser?.login);
    if (returnedUserId !== githubUserId) {
      throw new Error("Authenticated GitHub identity does not match the hosted session.");
    }
    accessible = await options.transport.getAccessibleInstallation(installationId);
  } catch (error) {
    if (error instanceof Error && error.message === "Authenticated GitHub identity does not match the hosted session.") throw error;
    throw new Error("GitHub installation re-verification failed.");
  }

  const observation = definitiveInstallation(accessible, installationId);
  try {
    if (observation.status === "revoked") {
      const result = await options.store.finishRevoked({ ...fence, reason: observation.reason });
      return finishEvidence(result, fence, observation.reason);
    }

    const verified = observation.value;
    if (verified.account.id !== fence.accountId || verified.account.type !== fence.accountType) {
      const result = await options.store.finishRevoked({ ...fence, reason: "account-identity-changed" });
      return finishEvidence(result, fence, "account-identity-changed");
    }
    const result = await options.store.finishVerified({
      ...fence,
      accountLogin: accountLogin(verified.account.login),
    });
    return finishEvidence(result, fence);
  } catch (error) {
    if (error instanceof Error && (
      error.message === "Hosted installation ownership changed during re-verification."
      || error.message === "Hosted installation re-verification store returned an invalid result."
    )) throw error;
    throw new Error("Hosted installation re-verification persistence failed.");
  }
}

export async function isSynSecHostedInstallationFreshlyAuthorized(options: {
  tenantId: string;
  installationId: number;
  maxAgeMs: number;
  store: SynSecHostedInstallationReverificationStore;
}): Promise<boolean> {
  const tenantId = boundedIdentifier(options?.tenantId, "Hosted tenant id");
  const installationId = positiveInteger(options?.installationId, "GitHub installation id");
  const maxAgeMs = options?.maxAgeMs;
  if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < MIN_FRESHNESS_MS || maxAgeMs > MAX_FRESHNESS_MS) {
    throw new Error(`Hosted installation verification freshness must be between ${MIN_FRESHNESS_MS} and ${MAX_FRESHNESS_MS} milliseconds.`);
  }
  if (!options.store || typeof options.store.isFreshlyAuthorized !== "function") {
    throw new Error("Hosted installation re-verification store is required.");
  }
  try {
    return await options.store.isFreshlyAuthorized(tenantId, installationId, maxAgeMs);
  } catch {
    throw new Error("Hosted installation authorization freshness check failed.");
  }
}
