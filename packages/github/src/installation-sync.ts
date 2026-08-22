import { verifyGitHubWebhookSignature, type GitHubWebhookSecret } from "./app.js";
import { validateGitHubRepositoryIdentity } from "./repository-acquisition.js";
import type {
  GitHubInstallationRecord,
  GitHubInstallationRecordInput,
  GitHubRepositorySelection,
} from "./installation-store.js";

const MAX_REPOSITORIES = 10_000;
const MAX_LOGIN_LENGTH = 255;
const SUPPORTED_INSTALLATION_ACTIONS = new Set(["created", "deleted", "suspend", "unsuspend", "new_permissions_accepted"]);
const SUPPORTED_REPOSITORY_ACTIONS = new Set(["added", "removed"]);

export interface GitHubInstallationStateStore {
  get(installationId: number): Promise<GitHubInstallationRecord | undefined>;
  put(input: GitHubInstallationRecordInput): Promise<GitHubInstallationRecord>;
  remove(installationId: number): Promise<boolean>;
}

export interface GitHubInstallationStateEvent {
  event: "installation" | "installation_repositories";
  action: string;
  installationId: number;
  accountLogin?: string;
  accountType?: "User" | "Organization";
  repositorySelection?: GitHubRepositorySelection;
  suspendedAt?: string;
  repositories: string[];
  repositoriesAdded: string[];
  repositoriesRemoved: string[];
}

export type GitHubInstallationSyncResult =
  | { status: "updated"; record: GitHubInstallationRecord }
  | { status: "removed"; installationId: number; existed: boolean };

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function requiredPositiveInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer.`);
  }
  return value;
}

function requiredString(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string") throw new Error(`${label} must be a string.`);
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required.`);
  if (normalized.length > maxLength) throw new Error(`${label} exceeds ${maxLength} characters.`);
  return normalized;
}

function accountType(value: unknown): "User" | "Organization" {
  if (value !== "User" && value !== "Organization") {
    throw new Error("GitHub installation account type must be User or Organization.");
  }
  return value;
}

function repositorySelection(value: unknown): GitHubRepositorySelection {
  if (value !== "all" && value !== "selected") {
    throw new Error("GitHub installation repository selection must be all or selected.");
  }
  return value;
}

function optionalTimestamp(value: unknown): string | undefined {
  if (value === null || value === undefined) return undefined;
  const normalized = requiredString(value, "GitHub installation suspension timestamp", 64);
  if (!Number.isFinite(Date.parse(normalized))) {
    throw new Error("GitHub installation suspension timestamp must be an ISO timestamp.");
  }
  return normalized;
}

function repositoryList(value: unknown, label: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error(`${label} must be an array.`);
  if (value.length > MAX_REPOSITORIES) throw new Error(`${label} exceeds ${MAX_REPOSITORIES} repositories.`);
  const names = value.map((entry) => {
    const fullName = objectValue(entry)?.full_name;
    if (typeof fullName !== "string") throw new Error(`${label} contains a repository without full_name.`);
    return validateGitHubRepositoryIdentity(fullName);
  });
  return [...new Set(names)].sort();
}

/**
 * Verify and normalize only GitHub installation-management state required for authorization.
 * Clone/API URLs, permissions, tokens, and arbitrary payload fields are intentionally discarded.
 */
export function parseVerifiedGitHubInstallationStateEvent(input: {
  body: string | Uint8Array;
  signatureHeader?: string;
  webhookSecret: GitHubWebhookSecret;
  eventName: string;
}): GitHubInstallationStateEvent {
  if (input.eventName !== "installation" && input.eventName !== "installation_repositories") {
    throw new Error("GitHub installation state synchronization accepts only installation management events.");
  }
  if (!verifyGitHubWebhookSignature(input.body, input.signatureHeader, input.webhookSecret)) {
    throw new Error("GitHub webhook signature verification failed.");
  }

  let payload: Record<string, unknown>;
  try {
    const parsed = JSON.parse(Buffer.from(input.body).toString("utf8"));
    const object = objectValue(parsed);
    if (!object) throw new Error();
    payload = object;
  } catch {
    throw new Error("GitHub installation webhook body must be a JSON object.");
  }

  const action = requiredString(payload.action, "GitHub installation action", 64);
  const installation = objectValue(payload.installation);
  if (!installation) throw new Error("GitHub installation webhook is missing installation metadata.");
  const installationId = requiredPositiveInteger(installation.id, "GitHub installation id");

  if (input.eventName === "installation") {
    if (!SUPPORTED_INSTALLATION_ACTIONS.has(action)) {
      throw new Error(`Unsupported GitHub installation action: ${action}`);
    }
    if (action === "deleted") {
      return {
        event: "installation",
        action,
        installationId,
        repositories: [],
        repositoriesAdded: [],
        repositoriesRemoved: [],
      };
    }
  } else if (!SUPPORTED_REPOSITORY_ACTIONS.has(action)) {
    throw new Error(`Unsupported GitHub installation_repositories action: ${action}`);
  }

  const account = objectValue(installation.account);
  if (!account) throw new Error("GitHub installation webhook is missing account metadata.");
  const selection = repositorySelection(installation.repository_selection);
  const repositories = selection === "all" ? [] : repositoryList(payload.repositories, "GitHub installation repositories");
  const suspendedAt = optionalTimestamp(installation.suspended_at);

  return {
    event: input.eventName,
    action,
    installationId,
    accountLogin: requiredString(account.login, "GitHub installation account login", MAX_LOGIN_LENGTH),
    accountType: accountType(account.type),
    repositorySelection: selection,
    ...(suspendedAt ? { suspendedAt } : {}),
    repositories,
    repositoriesAdded: repositoryList(payload.repositories_added, "GitHub added repositories"),
    repositoriesRemoved: repositoryList(payload.repositories_removed, "GitHub removed repositories"),
  };
}

function requireMetadata(event: GitHubInstallationStateEvent): {
  accountLogin: string;
  accountType: "User" | "Organization";
  repositorySelection: GitHubRepositorySelection;
} {
  if (!event.accountLogin || !event.accountType || !event.repositorySelection) {
    throw new Error("GitHub installation event is missing normalized authorization metadata.");
  }
  return {
    accountLogin: event.accountLogin,
    accountType: event.accountType,
    repositorySelection: event.repositorySelection,
  };
}

/** Apply one already verified GitHub installation-management event to durable authorization state. */
export async function synchronizeGitHubInstallationState(
  event: GitHubInstallationStateEvent,
  store: GitHubInstallationStateStore,
  now = Date.now(),
): Promise<GitHubInstallationSyncResult> {
  if (!Number.isFinite(now) || now <= 0) throw new Error("GitHub installation synchronization clock must be a positive timestamp.");
  if (event.event === "installation" && event.action === "deleted") {
    const existed = await store.remove(event.installationId);
    return { status: "removed", installationId: event.installationId, existed };
  }

  const metadata = requireMetadata(event);
  const existing = await store.get(event.installationId);
  const updatedAt = new Date(now).toISOString();

  if (event.event === "installation_repositories") {
    if (!existing) throw new Error("GitHub installation repository selection changed before installation state was initialized.");
    if (existing.repositorySelection !== "selected" || metadata.repositorySelection !== "selected") {
      throw new Error("GitHub installation repository delta is inconsistent with repositorySelection=selected.");
    }
    if (existing.accountLogin !== metadata.accountLogin || existing.accountType !== metadata.accountType) {
      throw new Error("GitHub installation repository delta account identity does not match stored authorization state.");
    }
    const repositories = new Set(existing.repositories);
    for (const repository of event.repositoriesRemoved) repositories.delete(repository);
    for (const repository of event.repositoriesAdded) repositories.add(repository);
    const record = await store.put({
      installationId: event.installationId,
      accountLogin: existing.accountLogin,
      accountType: existing.accountType,
      repositorySelection: "selected",
      repositories: [...repositories],
      ...(existing.suspendedAt ? { suspendedAt: existing.suspendedAt } : {}),
      updatedAt,
    });
    return { status: "updated", record };
  }

  let repositories: string[] | undefined;
  if (metadata.repositorySelection === "selected") {
    if (event.action === "created") {
      repositories = event.repositories;
    } else {
      repositories = event.repositories.length > 0
        ? event.repositories
        : existing?.repositorySelection === "selected"
          ? existing.repositories
          : [];
    }
  }

  const suspendedAt = event.action === "unsuspend"
    ? undefined
    : event.action === "suspend"
      ? event.suspendedAt ?? updatedAt
      : event.suspendedAt;

  const record = await store.put({
    installationId: event.installationId,
    ...metadata,
    ...(repositories ? { repositories } : {}),
    ...(suspendedAt ? { suspendedAt } : {}),
    updatedAt,
  });
  return { status: "updated", record };
}

/** Verify, normalize, and synchronize one installation-management delivery. */
export async function synchronizeVerifiedGitHubInstallationWebhook(input: {
  body: string | Uint8Array;
  signatureHeader?: string;
  webhookSecret: GitHubWebhookSecret;
  eventName: string;
  store: GitHubInstallationStateStore;
  now?: number;
}): Promise<GitHubInstallationSyncResult> {
  const event = parseVerifiedGitHubInstallationStateEvent(input);
  return synchronizeGitHubInstallationState(event, input.store, input.now ?? Date.now());
}
