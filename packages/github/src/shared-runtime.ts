import type { GitHubWebhookSecret } from "./app.js";
import { createGitHubAppWebhookHttpHandler, type GitHubAppWebhookHttpOptions } from "./app-http.js";
import type { GitHubAppInstallationStore, GitHubWebhookReplayManager } from "./app-handler.js";
import type { GitHubScanJobEnqueuer } from "./app-dispatch.js";
import {
  runConfiguredGitHubAppWorkerOnce,
  type ConfiguredGitHubAppWorkerOptions,
} from "./app-worker-runner.js";
import type { GitHubAppWorkerQueue } from "./app-worker.js";
import type { GitHubAppSharedStateBackendContract } from "./shared-state-contract.js";
import { assessGitHubAppSharedStateConformanceEvidence } from "./shared-state-evidence.js";

export interface GitHubAppSharedRuntimeOptions {
  /** Concrete adapter/version declaration bound to the supplied conformance report. */
  backendContract: GitHubAppSharedStateBackendContract;
  /** Portable report produced by the real-backend adversarial conformance harness. */
  conformanceReport: unknown;
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
 * Composition fails closed unless the supplied versioned backend contract is paired with complete,
 * structurally valid conformance evidence for that exact adapter build. This still does not create a
 * database client or independently certify that the adapter's harness used a real backend; it makes
 * evidence consumption mandatory at the runtime integration boundary instead of trusting capability
 * declarations alone. Backend credentials remain owned by the adapter and are not accepted by this API.
 */
export function createGitHubAppSharedRuntime(options: GitHubAppSharedRuntimeOptions): GitHubAppSharedRuntime {
  const evidence = assessGitHubAppSharedStateConformanceEvidence(
    options.backendContract,
    options.conformanceReport,
  );
  if (!evidence.ready) {
    throw new Error(`GitHub App shared-state conformance evidence is not ready: ${evidence.issues.map((issue) => issue.code).join(", ")}`);
  }

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
