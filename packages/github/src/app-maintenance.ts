import type { SynSecGitHubAppDrainController } from "./app-drain.js";
import type { SynSecGitHubAppWorkerDrainController } from "./app-worker-drain.js";

const DEFAULT_TIMEOUT_MS = 30_000;
const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 5 * 60 * 1000;
const DEFAULT_POLL_INTERVAL_MS = 250;
const MIN_POLL_INTERVAL_MS = 10;
const MAX_POLL_INTERVAL_MS = 5_000;
const MAX_ACTIVE_LEASES = 1_000_000;

export interface SynSecGitHubAppMaintenanceOptions {
  webhookDrain: SynSecGitHubAppDrainController;
  workerDrain: SynSecGitHubAppWorkerDrainController;
  /**
   * Read the current durable fenced-lease count from the shared backend. This callback belongs to
   * trusted hosting code; repository content, webhook payloads, and scanner output must never supply it.
   */
  countActiveLeases(): Promise<number>;
  pollIntervalMs?: number;
}

export interface SynSecGitHubAppMaintenanceStatus {
  acceptingWebhooks: boolean;
  acceptingWorkerRuns: boolean;
  activeWebhookRequests: number;
  activeWorkerRuns: number;
}

export interface SynSecGitHubAppServiceStopEvidence {
  webhookAdmissionClosed: true;
  workerAdmissionClosed: true;
  localWebhookRequests: 0;
  localWorkerRuns: 0;
  /** Durable fenced leases observed after local admission was closed. */
  activeLeases: 0;
}

export interface SynSecGitHubAppMaintenanceController {
  beginDrain(): SynSecGitHubAppMaintenanceStatus;
  resumeAdmission(): SynSecGitHubAppMaintenanceStatus;
  status(): SynSecGitHubAppMaintenanceStatus;
  /**
   * Close both admission boundaries, wait for already-admitted local work, then require the trusted
   * durable backend observer to report zero active fenced leases before a service manager stops the
   * process. This method never stops/restarts a process or performs a deployment itself.
   */
  prepareForServiceStop(timeoutMs?: number): Promise<SynSecGitHubAppServiceStopEvidence>;
}

function boundedInteger(value: number | undefined, fallback: number, minimum: number, maximum: number, label: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < minimum || resolved > maximum) {
    throw new Error(`${label} must be an integer between ${minimum} and ${maximum} milliseconds.`);
  }
  return resolved;
}

function activeLeaseCount(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_ACTIVE_LEASES) {
    throw new Error("GitHub App durable active-lease observation is invalid.");
  }
  return value;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/**
 * Compose the enforced webhook and background-worker admission drains into one service-manager
 * maintenance boundary.
 *
 * The controller intentionally distinguishes local process evidence from durable shared-state
 * evidence. Local run/request counts prove only that operations admitted through these in-process
 * controllers have completed. A stop becomes eligible only after a caller-owned durable observer
 * independently reports zero fenced leases while both admission boundaries remain closed.
 *
 * Observer failures are converted to a categorical error so backend connection strings, queries,
 * customer data, or other untrusted diagnostic material are not reflected through this boundary.
 */
export function createSynSecGitHubAppMaintenanceController(
  options: SynSecGitHubAppMaintenanceOptions,
): SynSecGitHubAppMaintenanceController {
  if (!options || typeof options !== "object") throw new Error("GitHub App maintenance options are required.");
  if (!options.webhookDrain || typeof options.webhookDrain.beginDrain !== "function") {
    throw new Error("GitHub App webhook drain controller is required.");
  }
  if (!options.workerDrain || typeof options.workerDrain.beginDrain !== "function") {
    throw new Error("GitHub App worker drain controller is required.");
  }
  if (typeof options.countActiveLeases !== "function") {
    throw new Error("GitHub App durable active-lease observer is required.");
  }
  const pollIntervalMs = boundedInteger(
    options.pollIntervalMs,
    DEFAULT_POLL_INTERVAL_MS,
    MIN_POLL_INTERVAL_MS,
    MAX_POLL_INTERVAL_MS,
    "GitHub App maintenance poll interval",
  );

  const currentStatus = (): SynSecGitHubAppMaintenanceStatus => {
    const webhooks = options.webhookDrain.status();
    const workers = options.workerDrain.status();
    return {
      acceptingWebhooks: webhooks.acceptingWebhooks,
      acceptingWorkerRuns: workers.acceptingWorkerRuns,
      activeWebhookRequests: webhooks.activeWebhookRequests,
      activeWorkerRuns: workers.activeWorkerRuns,
    };
  };

  const beginDrain = (): SynSecGitHubAppMaintenanceStatus => {
    options.webhookDrain.beginDrain();
    options.workerDrain.beginDrain();
    return currentStatus();
  };

  return {
    beginDrain,
    resumeAdmission() {
      options.webhookDrain.resumeAdmission();
      options.workerDrain.resumeAdmission();
      return currentStatus();
    },
    status: currentStatus,
    async prepareForServiceStop(timeoutMs?: number): Promise<SynSecGitHubAppServiceStopEvidence> {
      const timeout = boundedInteger(
        timeoutMs,
        DEFAULT_TIMEOUT_MS,
        MIN_TIMEOUT_MS,
        MAX_TIMEOUT_MS,
        "GitHub App maintenance timeout",
      );
      const startedAt = Date.now();
      beginDrain();

      const remaining = (): number => Math.max(0, timeout - (Date.now() - startedAt));
      const localTimeout = remaining();
      if (localTimeout < MIN_TIMEOUT_MS) {
        throw new Error("GitHub App maintenance drain did not complete before the configured timeout.");
      }
      try {
        await Promise.all([
          options.webhookDrain.waitForDrained(localTimeout),
          options.workerDrain.waitForDrained(localTimeout),
        ]);
      } catch {
        throw new Error("GitHub App maintenance drain did not complete before the configured timeout.");
      }

      for (;;) {
        if (remaining() <= 0) {
          throw new Error("GitHub App durable leases did not drain before the configured timeout.");
        }
        let leases: number;
        try {
          leases = activeLeaseCount(await options.countActiveLeases());
        } catch {
          throw new Error("GitHub App durable active-lease observation failed.");
        }
        if (leases === 0) {
          const status = currentStatus();
          if (status.acceptingWebhooks || status.acceptingWorkerRuns || status.activeWebhookRequests !== 0 || status.activeWorkerRuns !== 0) {
            throw new Error("GitHub App admission state changed while preparing for service stop.");
          }
          return {
            webhookAdmissionClosed: true,
            workerAdmissionClosed: true,
            localWebhookRequests: 0,
            localWorkerRuns: 0,
            activeLeases: 0,
          };
        }
        await sleep(Math.min(pollIntervalMs, remaining()));
      }
    },
  };
}
