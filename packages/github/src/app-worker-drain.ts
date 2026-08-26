const DEFAULT_DRAIN_TIMEOUT_MS = 30_000;
const MIN_DRAIN_TIMEOUT_MS = 1_000;
const MAX_DRAIN_TIMEOUT_MS = 120_000;

export interface SynSecGitHubAppWorkerDrainStatus {
  acceptingWorkerRuns: boolean;
  activeWorkerRuns: number;
}

export type SynSecGitHubAppWorkerAdmissionResult<T> =
  | { admitted: true; value: T }
  | { admitted: false };

export interface SynSecGitHubAppWorkerDrainController {
  beginDrain(): SynSecGitHubAppWorkerDrainStatus;
  resumeAdmission(): SynSecGitHubAppWorkerDrainStatus;
  status(): SynSecGitHubAppWorkerDrainStatus;
  run<T>(operation: () => Promise<T>): Promise<SynSecGitHubAppWorkerAdmissionResult<T>>;
  waitForDrained(timeoutMs?: number): Promise<void>;
}

function boundedTimeout(value: number | undefined): number {
  const resolved = value ?? DEFAULT_DRAIN_TIMEOUT_MS;
  if (!Number.isSafeInteger(resolved) || resolved < MIN_DRAIN_TIMEOUT_MS || resolved > MAX_DRAIN_TIMEOUT_MS) {
    throw new Error(
      `GitHub App worker drain timeout must be between ${MIN_DRAIN_TIMEOUT_MS} and ${MAX_DRAIN_TIMEOUT_MS} milliseconds.`,
    );
  }
  return resolved;
}

/**
 * Enforce one replica's background-worker admission boundary during maintenance or rollout.
 *
 * beginDrain() is synchronous: after it returns, subsequent run() calls are rejected before their
 * operation executes, so a correctly integrated worker cannot reach queue.claimNext(). Operations
 * admitted before the boundary closed are allowed to finish normally, including lease heartbeat and
 * fenced terminal transitions owned by the worker. This controller never cancels or steals a lease.
 *
 * activeWorkerRuns counts only operations admitted through this in-process controller. It is not a
 * durable queue lease count and must not be used as fleet-wide drain proof after crashes/restarts.
 */
export function createSynSecGitHubAppWorkerDrainController(): SynSecGitHubAppWorkerDrainController {
  let acceptingWorkerRuns = true;
  let activeWorkerRuns = 0;
  const drainedWaiters = new Set<() => void>();

  const currentStatus = (): SynSecGitHubAppWorkerDrainStatus => ({
    acceptingWorkerRuns,
    activeWorkerRuns,
  });

  const notifyDrained = (): void => {
    if (activeWorkerRuns !== 0) return;
    for (const resolve of drainedWaiters) resolve();
    drainedWaiters.clear();
  };

  return {
    beginDrain() {
      acceptingWorkerRuns = false;
      return currentStatus();
    },
    resumeAdmission() {
      acceptingWorkerRuns = true;
      return currentStatus();
    },
    status: currentStatus,
    async run<T>(operation: () => Promise<T>): Promise<SynSecGitHubAppWorkerAdmissionResult<T>> {
      if (typeof operation !== "function") throw new Error("GitHub App worker operation is required.");
      if (!acceptingWorkerRuns) return { admitted: false };

      activeWorkerRuns += 1;
      try {
        return { admitted: true, value: await operation() };
      } finally {
        activeWorkerRuns -= 1;
        notifyDrained();
      }
    },
    async waitForDrained(timeoutMs?: number): Promise<void> {
      if (acceptingWorkerRuns) {
        throw new Error("GitHub App worker admission must be draining before waiting for worker runs to drain.");
      }
      if (activeWorkerRuns === 0) return;
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
          reject(new Error("GitHub App worker admission drain did not complete before the configured timeout."));
        }, timeout);
        timer.unref?.();
        if (activeWorkerRuns === 0) onDrained();
      });
    },
  };
}
