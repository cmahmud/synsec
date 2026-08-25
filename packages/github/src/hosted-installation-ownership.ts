const MAX_IDENTIFIER_LENGTH = 128;
const MAX_LOGIN_LENGTH = 255;

export interface SynSecHostedGitHubPrincipal {
  /** Stable authenticated application subject. Never derived from repository-controlled input. */
  subject: string;
  /** Stable hosted tenant identifier chosen by the trusted application identity layer. */
  tenantId: string;
  /** GitHub user id bound to the authenticated session by the caller-owned identity layer. */
  githubUserId: number;
}

export interface SynSecAccessibleGitHubInstallation {
  id: number;
  account: {
    id: number;
    login: string;
    type: "User" | "Organization";
  };
  repositorySelection: "all" | "selected";
  suspendedAt?: string;
}

export interface SynSecGitHubUserInstallationTransport {
  /** Must execute with the same user-scoped GitHub credential used for getAccessibleInstallation(). */
  getAuthenticatedUser(): Promise<{ id: number; login: string }>;
  /** Return undefined when this authenticated GitHub user cannot access the requested installation. */
  getAccessibleInstallation(installationId: number): Promise<SynSecAccessibleGitHubInstallation | undefined>;
}

export interface SynSecHostedInstallationOwnershipClaim {
  tenantId: string;
  installationId: number;
  githubUserId: number;
  accountId: number;
  accountLogin: string;
  accountType: "User" | "Organization";
}

export type SynSecHostedInstallationClaimResult = "claimed" | "already-owned-by-tenant" | "conflict";

export interface SynSecHostedInstallationOwnershipStore {
  /** Atomic compare-and-claim. Implementations must never overwrite a different tenant owner. */
  claim(input: SynSecHostedInstallationOwnershipClaim): Promise<SynSecHostedInstallationClaimResult>;
}

export interface SynSecHostedInstallationOwnershipEvidence {
  status: "verified";
  tenantId: string;
  installationId: number;
  githubUserId: number;
  accountId: number;
  accountLogin: string;
  accountType: "User" | "Organization";
  repositorySelection: "all" | "selected";
  ownership: "claimed" | "already-owned-by-tenant";
  interpretation: "authenticated-user-access-and-atomic-tenant-claim-only";
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

function login(value: unknown): string {
  if (typeof value !== "string") throw new Error("GitHub account login must be a string.");
  const normalized = value.trim();
  if (!normalized || normalized.length > MAX_LOGIN_LENGTH || /[\u0000-\u001f\u007f]/.test(normalized)) {
    throw new Error("GitHub account login is invalid.");
  }
  return normalized;
}

function installation(value: SynSecAccessibleGitHubInstallation | undefined, expectedId: number): SynSecAccessibleGitHubInstallation {
  if (!value || typeof value !== "object") throw new Error("GitHub installation is not accessible to the authenticated user.");
  if (positiveInteger(value.id, "GitHub installation id") !== expectedId) {
    throw new Error("GitHub installation lookup returned an unexpected installation.");
  }
  if (!value.account || typeof value.account !== "object") throw new Error("GitHub installation account is invalid.");
  positiveInteger(value.account.id, "GitHub installation account id");
  login(value.account.login);
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
    throw new Error("Suspended GitHub installations cannot be claimed for hosted use.");
  }
  return value;
}

/**
 * Verify hosted installation ownership through a caller-owned user-scoped GitHub transport and then
 * atomically claim the installation for one hosted tenant.
 *
 * This function deliberately accepts no GitHub token. The transport owns user credentials and must
 * use the same authenticated GitHub identity for both calls. A successful result proves only that
 * the authenticated user id matched the caller-bound session, GitHub exposed the installation to
 * that user at verification time, and the ownership store accepted the tenant claim. It does not
 * prove organization role, future access, repository authorization, runtime route protection, or
 * that GitHub will continue to expose the installation.
 */
export async function verifyAndClaimSynSecHostedGitHubInstallation(options: {
  principal: SynSecHostedGitHubPrincipal;
  installationId: number;
  transport: SynSecGitHubUserInstallationTransport;
  store: SynSecHostedInstallationOwnershipStore;
}): Promise<SynSecHostedInstallationOwnershipEvidence> {
  if (!options || typeof options !== "object") throw new Error("Hosted GitHub installation verification options are required.");
  const subject = boundedIdentifier(options.principal?.subject, "Hosted principal subject");
  void subject; // validated as part of the authenticated-session boundary; intentionally not persisted here.
  const tenantId = boundedIdentifier(options.principal?.tenantId, "Hosted tenant id");
  const githubUserId = positiveInteger(options.principal?.githubUserId, "Authenticated GitHub user id");
  const installationId = positiveInteger(options.installationId, "GitHub installation id");
  if (!options.transport || typeof options.transport.getAuthenticatedUser !== "function" || typeof options.transport.getAccessibleInstallation !== "function") {
    throw new Error("User-scoped GitHub installation transport is required.");
  }
  if (!options.store || typeof options.store.claim !== "function") {
    throw new Error("Hosted installation ownership store is required.");
  }

  let authenticatedUser: { id: number; login: string };
  let accessible: SynSecAccessibleGitHubInstallation | undefined;
  try {
    authenticatedUser = await options.transport.getAuthenticatedUser();
    const returnedUserId = positiveInteger(authenticatedUser?.id, "GitHub authenticated user id");
    login(authenticatedUser?.login);
    if (returnedUserId !== githubUserId) {
      throw new Error("Authenticated GitHub identity does not match the hosted session.");
    }
    accessible = await options.transport.getAccessibleInstallation(installationId);
  } catch (error) {
    if (error instanceof Error && (
      error.message === "Authenticated GitHub identity does not match the hosted session."
      || error.message.startsWith("GitHub authenticated user id")
      || error.message.startsWith("GitHub account login")
    )) throw error;
    throw new Error("GitHub installation ownership verification failed.");
  }

  const verified = installation(accessible, installationId);
  const claim: SynSecHostedInstallationOwnershipClaim = {
    tenantId,
    installationId,
    githubUserId,
    accountId: positiveInteger(verified.account.id, "GitHub installation account id"),
    accountLogin: login(verified.account.login),
    accountType: verified.account.type,
  };

  let ownership: SynSecHostedInstallationClaimResult;
  try {
    ownership = await options.store.claim(claim);
  } catch {
    throw new Error("Hosted installation ownership persistence failed.");
  }
  if (ownership === "conflict") throw new Error("GitHub installation is already claimed by another hosted tenant.");
  if (ownership !== "claimed" && ownership !== "already-owned-by-tenant") {
    throw new Error("Hosted installation ownership store returned an invalid result.");
  }

  return {
    status: "verified",
    tenantId,
    installationId,
    githubUserId,
    accountId: claim.accountId,
    accountLogin: claim.accountLogin,
    accountType: claim.accountType,
    repositorySelection: verified.repositorySelection,
    ownership,
    interpretation: "authenticated-user-access-and-atomic-tenant-claim-only",
  };
}
