import type { GitHubWebhookSecret } from "./app.js";
import { createGitHubAppWebhookHttpHandler, type GitHubAppWebhookHttpOptions } from "./app-http.js";
import type { GitHubAppInstallationStore, GitHubWebhookReplayManager } from "./app-handler.js";
import type { GitHubScanJobEnqueuer } from "./app-dispatch.js";
import {
  runConfiguredGitHubAppWorkerOnce,
  type ConfiguredGitHubAppWorkerOptions,
} from "./app-worker-runner.js";
import type { GitHubAppWorkerQueue } from "./app-worker.js";
import {
  assertGitHubAppSharedStateBackendContract,
  type GitHubAppSharedStateBackendContract,
} from "./shared-state-contract.js";

export interface GitHubAppSharedRuntimeOptions {
  /** Concrete adapter/version declaration. Validating this is necessary but not backend certification. */
  backendContract: GitHubAppSharedStateBackendContract;
  webhookSecret: GitHubWebhookSecret;
  replayStore: GitHubWebhookReplayManager;
  installationStore: GitHubAppInstallationStore;
  queue: GitHubScanJobEnqueuer & GitHubAppWorkerQueue;
  webhookPath?: string;
  onWebhookError?: (error: unknown) => void;
  worker: Omit<ConfiguredGitHubAppWorkerOptions, "queue" | "installationStore">;
}

export interface GitHubAppSharedRuntime {
  backendId: string;
  implementationVersion: string;
  webhookHandler: ReturnType<typeof createGitHubAppWebhookHttpHandler>;
  runWorkerOnce(): ReturnType<typeof runConfiguredGitHubAppWorkerOnce>;
}

/**
 * Compose externally implemented shared stores into SynSec's hosted intake/worker pipeline.
 *
 * This function deliberately does not create a database client or claim that supplied stores are
 * transactionally correct. It requires a complete versioned backend contract before composition,
 * then preserves the same replay, authorization, queue-fencing, exact-commit, and publication
 * boundaries used by the single-host runtime. Backend credentials remain owned by the adapter and
 * are not accepted by this API.
 */
export function createGitHubAppSharedRuntime(options: GitHubAppSharedRuntimeOptions): GitHubAppSharedRuntime {
  assertGitHubAppSharedStateBackendContract(options.backendContract);

  const httpOptions: GitHubAppWebhookHttpOptions = {
    webhookSecret: options.webhookSecret,
    replayStore: options.replayStore,
    installationStore: options.installationStore,
    queue: options.queue,
    ...(options.webhookPath ? { path: options.webhookPath } : {}),
    ...(options.onWebhookError ? { onError: options.onWebhookError } : {}),
  };
  const webhookHandler = createGitHubAppWebhookHttpHandler(httpOptions);
  const workerOptions: ConfiguredGitHubAppWorkerOptions = {
    ...options.worker,
    queue: options.queue,
    installationStore: options.installationStore,
  };

  return {
    backendId: options.backendContract.backendId,
    implementationVersion: options.backendContract.implementationVersion,
    webhookHandler,
    runWorkerOnce: () => runConfiguredGitHubAppWorkerOnce(workerOptions),
  };
}
