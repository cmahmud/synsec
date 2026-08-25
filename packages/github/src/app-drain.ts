import type { IncomingMessage, ServerResponse } from "node:http";

const DEFAULT_DRAIN_TIMEOUT_MS = 30_000;
const MIN_DRAIN_TIMEOUT_MS = 1_000;
const MAX_DRAIN_TIMEOUT_MS = 120_000;

export interface SynSecGitHubAppDrainStatus {
  acceptingWebhooks: boolean;
  activeWebhookRequests: number;
}

export interface SynSecGitHubAppDrainController {
  readonly webhookHandler: (request: IncomingMessage, response: ServerResponse) => Promise<void>;
  beginDrain(): SynSecGitHubAppDrainStatus;
  resumeAdmission(): SynSecGitHubAppDrainStatus;
  status(): SynSecGitHubAppDrainStatus;
  waitForDrained(timeoutMs?: number): Promise<void>;
}

function boundedTimeout(value: number | undefined): number {
  const resolved = value ?? DEFAULT_DRAIN_TIMEOUT_MS;
  if (!Number.isSafeInteger(resolved) || resolved < MIN_DRAIN_TIMEOUT_MS || resolved > MAX_DRAIN_TIMEOUT_MS) {
    throw new Error(
      `GitHub App drain timeout must be between ${MIN_DRAIN_TIMEOUT_MS} and ${MAX_DRAIN_TIMEOUT_MS} milliseconds.`,
    );
  }
  return resolved;
}

function sendDraining(response: ServerResponse): void {
  const body = '{"status":"draining"}\n';
  response.statusCode = 503;
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.setHeader("content-length", Buffer.byteLength(body));
  response.setHeader("cache-control", "no-store");
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("retry-after", "1");
  response.end(body);
}

/**
 * Wrap a GitHub App webhook handler with an enforced local admission-drain boundary.
 *
 * beginDrain() prevents new webhook requests from entering the wrapped handler while existing
 * requests are allowed to finish. Rejected requests receive a bounded aggregate-only 503 response
 * so GitHub can retry them; payloads, repository identities, delivery ids, and backend errors are
 * never reflected. waitForDrained() observes only the requests admitted through this controller.
 * It does not cancel workers, revoke queue leases, stop a process, or prove fleet-wide drainage.
 */
export function createSynSecGitHubAppDrainController(
  handler: (request: IncomingMessage, response: ServerResponse) => Promise<void>,
): SynSecGitHubAppDrainController {
  if (typeof handler !== "function") throw new Error("GitHub App webhook handler is required.");

  let acceptingWebhooks = true;
  let activeWebhookRequests = 0;
  const drainedWaiters = new Set<() => void>();

  const currentStatus = (): SynSecGitHubAppDrainStatus => ({
    acceptingWebhooks,
    activeWebhookRequests,
  });

  const notifyDrained = (): void => {
    if (activeWebhookRequests !== 0) return;
    for (const resolve of drainedWaiters) resolve();
    drainedWaiters.clear();
  };

  const webhookHandler = async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    if (!acceptingWebhooks) {
      sendDraining(response);
      return;
    }

    activeWebhookRequests += 1;
    try {
      await handler(request, response);
    } finally {
      activeWebhookRequests -= 1;
      notifyDrained();
    }
  };

  return {
    webhookHandler,
    beginDrain() {
      acceptingWebhooks = false;
      return currentStatus();
    },
    resumeAdmission() {
      acceptingWebhooks = true;
      return currentStatus();
    },
    status: currentStatus,
    async waitForDrained(timeoutMs?: number): Promise<void> {
      if (activeWebhookRequests === 0) return;
      const timeout = boundedTimeout(timeoutMs);
      await new Promise<void>((resolve, reject) => {
        let settled = false;
        let timer: NodeJS.Timeout;
        const onDrained = (): void => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          drainedWaiters.delete(onDrained);
          resolve();
        };
        drainedWaiters.add(onDrained);
        timer = setTimeout(() => {
          if (settled) return;
          settled = true;
          drainedWaiters.delete(onDrained);
          reject(new Error("GitHub App webhook admission drain did not complete before the configured timeout."));
        }, timeout);
        timer.unref?.();
        if (activeWebhookRequests === 0) onDrained();
      });
    },
  };
}
