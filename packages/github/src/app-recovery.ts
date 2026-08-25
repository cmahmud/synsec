import type {
  SynSecGitHubAppMaintenanceController,
  SynSecGitHubAppMaintenanceStatus,
} from "./app-maintenance.js";

const DEFAULT_TIMEOUT_MS = 30_000;
const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 5 * 60 * 1000;
const DEFAULT_POLL_INTERVAL_MS = 250;
const MIN_POLL_INTERVAL_MS = 10;
const MAX_POLL_INTERVAL_MS = 5_000;

export type SynSecGitHubAppRecoveryReason =
  | "shared-state-unavailable"
  | "runtime-credentials-unavailable"
  | "github-control-plane-unavailable"
  | "operator";

export type SynSecGitHubAppRecoveryState =
  | "running"
  | "isolated"
  | "verifying"
  | "recovery-failed";

export interface SynSecGitHubAppRecoveryStatus {
  state: SynSecGitHubAppRecoveryState;
  reason?: SynSecGitHubAppRecoveryReason;
  attempts: number;
  interpretation: "local-admission-recovery-boundary-not-external-health-proof";
}

export interface SynSecGitHubAppRecoveryProbeResult {
  sharedStateReady: boolean;
  runtimeCredentialsReady: boolean;
  githubControlPlaneReady: boolean;
}

export interface SynSecGitHubAppRecoveryOptions {
  maintenance: SynSecGitHubAppMaintenanceController;
  /**
   * Trusted hosting probe. It owns database/GitHub/secret-manager credentials and returns only
   * booleans. Repository content, webhook payloads, scanner output, and stored artifacts must never
   * supply this callback or its result.
   *
   * A true value is operator/runtime evidence only. In particular, runtimeCredentialsReady does not
   * prove GitHub has accepted a newly rolled credential unless the hosting probe actually performs
   * that check, and githubControlPlaneReady does not establish repository authorization.
   */
  probe(): Promise<SynSecGitHubAppRecoveryProbeResult>;
  pollIntervalMs?: number;
}

export interface SynSecGitHubAppRecoveryController {
  status(): SynSecGitHubAppRecoveryStatus;
  /** Immediately close local webhook and worker admission for a categorical incident. */
  isolate(reason: SynSecGitHubAppRecoveryReason): SynSecGitHubAppRecoveryStatus;
  /**
   * Wait for locally admitted work to finish, then require every trusted recovery probe to pass
   * before reopening admission. Concurrent callers share one recovery attempt.
   */
  recover(timeoutMs?: number): Promise<SynSecGitHubAppRecoveryStatus>;
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  label: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < minimum || resolved > maximum) {
    throw new Error(`${label} must be an integer between ${minimum} and ${maximum} milliseconds.`);
  }
  return resolved;
}

function validateReason(value: SynSecGitHubAppRecoveryReason): SynSecGitHubAppRecoveryReason {
  if (
    value !== "shared-state-unavailable"
    && value !== "runtime-credentials-unavailable"
    && value !== "github-control-plane-unavailable"
    && value !== "operator"
  ) {
    throw new Error("GitHub App recovery reason is invalid.");
  }
  return value;
}

function localDrainComplete(status: SynSecGitHubAppMaintenanceStatus): boolean {
  return status.acceptingWebhooks === false
    && status.acceptingWorkerRuns === false
    && status.activeWebhookRequests === 0
    && status.activeWorkerRuns === 0;
}

function validProbeResult(value: unknown): value is SynSecGitHubAppRecoveryProbeResult {
  if (!value || typeof value !== "object") return false;
  const result = value as Partial<SynSecGitHubAppRecoveryProbeResult>;
  return typeof result.sharedStateReady === "boolean"
    && typeof result.runtimeCredentialsReady === "boolean"
    && typeof result.githubControlPlaneReady === "boolean";
}

function allReady(result: SynSecGitHubAppRecoveryProbeResult): boolean {
  return result.sharedStateReady && result.runtimeCredentialsReady && result.githubControlPlaneReady;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Enforce a process-local recovery boundary around GitHub App admission.
 *
 * isolate() synchronously closes both webhook and worker admission through the existing maintenance
 * controller. recover() never invokes the trusted probe while pre-isolation local work is still
 * active, and never resumes admission until all three recovery prerequisites report ready in one
 * probe observation. A thrown/malformed probe fails closed with a categorical status and leaves
 * admission closed; original diagnostics are intentionally discarded.
 *
 * This controller does not restart processes, mutate durable queue/tenant state, release ownership
 * fences, certify PostgreSQL/GitHub/secret-manager health, or coordinate recovery across replicas.
 * Those remain external trust boundaries. Multi-replica operators must isolate/recover each replica
 * under their service manager and continue relying on SynSec's durable fencing/authorization checks.
 */
export function createSynSecGitHubAppRecoveryController(
  options: SynSecGitHubAppRecoveryOptions,
): SynSecGitHubAppRecoveryController {
  if (!options || typeof options !== "object") throw new Error("GitHub App recovery options are required.");
  if (
    !options.maintenance
    || typeof options.maintenance.beginDrain !== "function"
    || typeof options.maintenance.resumeAdmission !== "function"
    || typeof options.maintenance.status !== "function"
  ) {
    throw new Error("GitHub App maintenance controller is required.");
  }
  if (typeof options.probe !== "function") throw new Error("GitHub App recovery probe is required.");
  const pollIntervalMs = boundedInteger(
    options.pollIntervalMs,
    DEFAULT_POLL_INTERVAL_MS,
    MIN_POLL_INTERVAL_MS,
    MAX_POLL_INTERVAL_MS,
    "GitHub App recovery poll interval",
  );

  let state: SynSecGitHubAppRecoveryState = "running";
  let reason: SynSecGitHubAppRecoveryReason | undefined;
  let attempts = 0;
  let inFlight: Promise<SynSecGitHubAppRecoveryStatus> | undefined;

  const current = (): SynSecGitHubAppRecoveryStatus => ({
    state,
    ...(reason ? { reason } : {}),
    attempts,
    interpretation: "local-admission-recovery-boundary-not-external-health-proof",
  });

  return {
    status: current,
    isolate(requestedReason) {
      const validatedReason = validateReason(requestedReason);
      if (inFlight) {
        throw new Error("GitHub App recovery verification is already in progress.");
      }
      options.maintenance.beginDrain();
      state = "isolated";
      reason = validatedReason;
      return current();
    },
    recover(timeoutMs) {
      if (state === "running") return Promise.resolve(current());
      if (inFlight) return inFlight;
      const timeout = boundedInteger(
        timeoutMs,
        DEFAULT_TIMEOUT_MS,
        MIN_TIMEOUT_MS,
        MAX_TIMEOUT_MS,
        "GitHub App recovery timeout",
      );
      const startedAt = Date.now();
      state = "verifying";
      inFlight = (async () => {
        try {
          for (;;) {
            const elapsed = Date.now() - startedAt;
            if (elapsed >= timeout) {
              state = "recovery-failed";
              return current();
            }

            const maintenanceStatus = options.maintenance.status();
            if (
              maintenanceStatus.acceptingWebhooks
              || maintenanceStatus.acceptingWorkerRuns
            ) {
              state = "recovery-failed";
              return current();
            }

            if (!localDrainComplete(maintenanceStatus)) {
              await sleep(Math.min(pollIntervalMs, Math.max(1, timeout - elapsed)));
              continue;
            }

            attempts += 1;
            let probe: SynSecGitHubAppRecoveryProbeResult;
            try {
              const observed = await options.probe();
              if (!validProbeResult(observed)) {
                state = "recovery-failed";
                return current();
              }
              probe = observed;
            } catch {
              state = "recovery-failed";
              return current();
            }

            if (allReady(probe)) {
              const beforeResume = options.maintenance.status();
              if (!localDrainComplete(beforeResume)) {
                state = "recovery-failed";
                return current();
              }
              options.maintenance.resumeAdmission();
              state = "running";
              reason = undefined;
              return current();
            }

            const remaining = timeout - (Date.now() - startedAt);
            if (remaining <= 0) {
              state = "recovery-failed";
              return current();
            }
            await sleep(Math.min(pollIntervalMs, remaining));
          }
        } finally {
          inFlight = undefined;
        }
      })();
      return inFlight;
    },
  };
}
