import { mkdir } from "node:fs/promises";
import { isAbsolute, join, relative, resolve } from "node:path";
import type { SynSecConfig } from "@synsec/config";
import type { ApprovedRemediationExecution } from "@synsec/workflows/remediation";
import { createGitHubAppWebhookHttpHandler } from "./app-http.js";
import { buildGitHubAppRuntimeStatus, type GitHubAppRuntimeStatus } from "./app-status.js";
import { createGitHubAppInstallationTokenProvider } from "./app-token-provider.js";
import { runConfiguredGitHubAppWorkerOnce, type ConfiguredGitHubAppWorkerOptions } from "./app-worker-runner.js";
import { FileGitHubInstallationStore } from "./installation-store.js";
import { FileGitHubWebhookReplayStore } from "./replay-store.js";
import { pruneGitHubAppFailedJobs, type GitHubAppRetentionResult } from "./retention.js";
import { acquireGitHubRepositoryCommit } from "./repository-acquisition.js";
import {
  createApprovedGitHubRemediationPullRequest,
  type GitHubRemediationPullRequestResult,
} from "./remediation-writer.js";
import { FileGitHubScanQueue } from "./scan-queue.js";
import type { GitHubCheckThreshold } from "./index.js";
import type { GitHubPublisherOptions } from "./publisher.js";

export interface LocalGitHubAppRuntimeOptions extends GitHubPublisherOptions {
  stateDirectory: string;
  workspaceRoot: string;
  webhookSecret: string;
  appId: string | number;
  privateKey: string;
  config: SynSecConfig;
  webhookPath?: string;
  replayRetentionMs?: number;
  queueLeaseMs?: number;
  failedJobRetentionMs?: number;
  retentionMaxDeletes?: number;
  threshold?: GitHubCheckThreshold;
  publishSarif?: boolean;
  toolVersion?: string;
  onWebhookError?: (error: unknown) => void;
  now?: () => number;
}

export interface LocalGitHubAppMaintenanceResult {
  expiredReplayRecordsDeleted: number;
  failedJobs: GitHubAppRetentionResult;
}

export interface LocalGitHubAppRemediationInput {
  installationId: number;
  repository: string;
  baseBranch: string;
  execution: ApprovedRemediationExecution;
}

export interface LocalGitHubAppRuntime {
  stateDirectory: string;
  workspaceRoot: string;
  replayStore: FileGitHubWebhookReplayStore;
  installationStore: FileGitHubInstallationStore;
  queue: FileGitHubScanQueue;
  webhookHandler: ReturnType<typeof createGitHubAppWebhookHttpHandler>;
  runWorkerOnce(): ReturnType<typeof runConfiguredGitHubAppWorkerOnce>;
  runMaintenance(): Promise<LocalGitHubAppMaintenanceResult>;
  getStatus(): Promise<GitHubAppRuntimeStatus>;
  createRemediationPullRequest(input: LocalGitHubAppRemediationInput): Promise<GitHubRemediationPullRequestResult>;
}

function requiredDirectory(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required.`);
  return resolve(normalized);
}

function isSameOrDescendant(parent: string, candidate: string): boolean {
  const path = relative(parent, candidate);
  return path === "" || (!isAbsolute(path) && path !== ".." && !path.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`));
}

function pathsOverlap(a: string, b: string): boolean {
  return isSameOrDescendant(a, b) || isSameOrDescendant(b, a);
}

/**
 * Compose SynSec's single-host GitHub App primitives without opening a network listener.
 *
 * State and source workspaces must be separate directory trees so scanner working copies are never
 * created inside durable authorization/queue storage. App credentials remain in the returned
 * token-provider closure only; they are not written to any local store. The token provider also
 * fails closed when GitHub reports that the installation lacks the permissions required for
 * repository acquisition, publication, or an explicitly invoked approved remediation write. The
 * caller still owns TLS, listener binding, process/container isolation, network policy, and secret
 * injection/rotation.
 */
export async function createLocalGitHubAppRuntime(options: LocalGitHubAppRuntimeOptions): Promise<LocalGitHubAppRuntime> {
  const stateDirectory = requiredDirectory(options.stateDirectory, "GitHub App state directory");
  const workspaceRoot = requiredDirectory(options.workspaceRoot, "GitHub App workspace root");
  if (pathsOverlap(stateDirectory, workspaceRoot)) {
    throw new Error("GitHub App state directory and workspace root must be separate directory trees.");
  }
  if (!options.webhookSecret.trim()) throw new Error("GitHub App webhook secret is required.");

  await mkdir(stateDirectory, { recursive: true, mode: 0o700 });
  await mkdir(workspaceRoot, { recursive: true, mode: 0o700 });

  const replayStore = new FileGitHubWebhookReplayStore(join(stateDirectory, "replay"), {
    ...(options.replayRetentionMs !== undefined ? { retentionMs: options.replayRetentionMs } : {}),
    ...(options.now ? { now: options.now } : {}),
  });
  const installationStore = new FileGitHubInstallationStore(join(stateDirectory, "installations"));
  const queue = new FileGitHubScanQueue(join(stateDirectory, "queue"), {
    ...(options.queueLeaseMs !== undefined ? { leaseMs: options.queueLeaseMs } : {}),
    ...(options.now ? { now: options.now } : {}),
  });
  const getInstallationToken = createGitHubAppInstallationTokenProvider({
    appId: options.appId,
    privateKey: options.privateKey,
    requiredPermissionsByPurpose: {
      acquire: { contents: "read" },
      publish: {
        checks: "write",
        ...(options.publishSarif ? { security_events: "write" as const } : {}),
      },
      remediate: {
        contents: "write",
        pull_requests: "write",
      },
    },
    ...(options.apiVersion ? { apiVersion: options.apiVersion } : {}),
    ...(options.userAgent ? { userAgent: options.userAgent } : {}),
    ...(options.fetch ? { fetch: options.fetch } : {}),
    ...(options.now ? { now: options.now } : {}),
  });

  const webhookHandler = createGitHubAppWebhookHttpHandler({
    webhookSecret: options.webhookSecret,
    replayStore,
    installationStore,
    queue,
    ...(options.webhookPath ? { path: options.webhookPath } : {}),
    ...(options.onWebhookError ? { onError: options.onWebhookError } : {}),
  });

  const workerOptions: ConfiguredGitHubAppWorkerOptions = {
    queue,
    installationStore,
    config: options.config,
    getInstallationToken,
    acquisitionOptions: { workspaceRoot },
    ...(options.threshold ? { threshold: options.threshold } : {}),
    ...(options.publishSarif !== undefined ? { publishSarif: options.publishSarif } : {}),
    ...(options.toolVersion ? { toolVersion: options.toolVersion } : {}),
    ...(options.apiVersion ? { apiVersion: options.apiVersion } : {}),
    ...(options.userAgent ? { userAgent: options.userAgent } : {}),
    ...(options.fetch ? { fetch: options.fetch } : {}),
  };

  return {
    stateDirectory,
    workspaceRoot,
    replayStore,
    installationStore,
    queue,
    webhookHandler,
    runWorkerOnce: () => runConfiguredGitHubAppWorkerOnce(workerOptions),
    runMaintenance: async () => ({
      expiredReplayRecordsDeleted: await replayStore.pruneExpired(),
      failedJobs: await pruneGitHubAppFailedJobs(queue, {
        ...(options.failedJobRetentionMs !== undefined ? { failedJobRetentionMs: options.failedJobRetentionMs } : {}),
        ...(options.retentionMaxDeletes !== undefined ? { maxDeletes: options.retentionMaxDeletes } : {}),
        ...(options.now ? { now: options.now } : {}),
      }),
    }),
    getStatus: () => buildGitHubAppRuntimeStatus({ installationStore, queue }),
    createRemediationPullRequest: async (input) => {
      if (!(await installationStore.isRepositoryAllowed(input.installationId, input.repository))) {
        throw new Error("GitHub installation is not authorized to remediate this repository.");
      }
      const token = await getInstallationToken(input.installationId, "remediate");
      const acquired = await acquireGitHubRepositoryCommit({
        repository: input.repository,
        commitSha: input.execution.targetCommitSha,
        installationToken: token,
      }, { workspaceRoot });
      try {
        return await createApprovedGitHubRemediationPullRequest({
          repository: input.repository,
          baseBranch: input.baseBranch,
          workspace: acquired.workspace,
          installationToken: token,
          execution: input.execution,
        }, {
          ...(options.apiVersion ? { apiVersion: options.apiVersion } : {}),
          ...(options.userAgent ? { userAgent: options.userAgent } : {}),
          ...(options.fetch ? { fetch: options.fetch } : {}),
        });
      } finally {
        await acquired.cleanup();
      }
    },
  };
}
