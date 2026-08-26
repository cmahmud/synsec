import type {
  SynSecGitHubAppMaintenanceController,
  SynSecGitHubAppServiceStopEvidence,
} from "./app-maintenance.js";

const DEFAULT_STOP_TIMEOUT_MS = 30_000;
const MIN_STOP_TIMEOUT_MS = 100;
const MAX_STOP_TIMEOUT_MS = 5 * 60 * 1000;

export type SynSecGitHubAppStopReason = "SIGTERM" | "SIGINT" | "operator";
export type SynSecGitHubAppServiceLifecycleState = "running" | "draining" | "ready-to-stop" | "stop-failed";

export interface SynSecGitHubAppServiceLifecycleStatus {
  state: SynSecGitHubAppServiceLifecycleState;
  reason?: SynSecGitHubAppStopReason;
}

export interface SynSecGitHubAppServiceLifecycleOptions {
  maintenance: SynSecGitHubAppMaintenanceController;
  timeoutMs?: number;
  /**
   * Trusted hosting callback invoked only after SynSec has closed admission, drained local work,
   * and observed zero durable fenced leases. This callback may hand control back to systemd,
   * Kubernetes, or another process supervisor. Repository/scanner input must never supply it.
   */
  onReadyToStop(
    evidence: SynSecGitHubAppServiceStopEvidence,
    reason: SynSecGitHubAppStopReason,
  ): void | Promise<void>;
  /** Optional categorical hosting notification. The original backend/process error is not exposed. */
  onStopFailed?(reason: SynSecGitHubAppStopReason): void | Promise<void>;
}

export interface SynSecGitHubAppServiceLifecycleController {
  status(): SynSecGitHubAppServiceLifecycleStatus;
  /** Serialized and idempotent while a stop attempt is in progress or has completed successfully. */
  requestStop(reason?: SynSecGitHubAppStopReason): Promise<SynSecGitHubAppServiceLifecycleStatus>;
  /** Resume only after a failed/aborted stop attempt. */
  resume(): SynSecGitHubAppServiceLifecycleStatus;
}

export interface SynSecGitHubAppSignalSource {
  on(signal: "SIGTERM" | "SIGINT", listener: () => void): unknown;
  off(signal: "SIGTERM" | "SIGINT", listener: () => void): unknown;
}

export interface SynSecGitHubAppSignalBinding {
  dispose(): void;
}

function boundedTimeout(value: number | undefined): number {
  const timeout = value ?? DEFAULT_STOP_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeout) || timeout < MIN_STOP_TIMEOUT_MS || timeout > MAX_STOP_TIMEOUT_MS) {
    throw new Error(`GitHub App service stop timeout must be an integer between ${MIN_STOP_TIMEOUT_MS} and ${MAX_STOP_TIMEOUT_MS} milliseconds.`);
  }
  return timeout;
}

/**
 * Bridge trusted process/service-manager stop requests into SynSec's enforced maintenance boundary.
 *
 * A successful lifecycle transition means only that this process closed its webhook/worker admission,
 * all locally admitted work completed, and the caller-owned durable observer reported zero current
 * fenced leases. It does not prove that another replica stopped, that a rollout completed, or that a
 * service manager accepted the handoff.
 */
export function createSynSecGitHubAppServiceLifecycleController(
  options: SynSecGitHubAppServiceLifecycleOptions,
): SynSecGitHubAppServiceLifecycleController {
  if (!options || typeof options !== "object") throw new Error("GitHub App service lifecycle options are required.");
  if (!options.maintenance || typeof options.maintenance.prepareForServiceStop !== "function") {
    throw new Error("GitHub App maintenance controller is required.");
  }
  if (typeof options.onReadyToStop !== "function") {
    throw new Error("GitHub App ready-to-stop callback is required.");
  }
  const timeoutMs = boundedTimeout(options.timeoutMs);

  let state: SynSecGitHubAppServiceLifecycleState = "running";
  let reason: SynSecGitHubAppStopReason | undefined;
  let inFlight: Promise<SynSecGitHubAppServiceLifecycleStatus> | undefined;

  const current = (): SynSecGitHubAppServiceLifecycleStatus => ({
    state,
    ...(reason ? { reason } : {}),
  });

  const controller: SynSecGitHubAppServiceLifecycleController = {
    status: current,
    requestStop(requestedReason = "operator") {
      if (state === "ready-to-stop") return Promise.resolve(current());
      if (inFlight) return inFlight;
      reason = requestedReason;
      state = "draining";
      inFlight = (async () => {
        try {
          const evidence = await options.maintenance.prepareForServiceStop(timeoutMs);
          await options.onReadyToStop(evidence, requestedReason);
          state = "ready-to-stop";
        } catch {
          state = "stop-failed";
          if (options.onStopFailed) {
            try {
              await options.onStopFailed(requestedReason);
            } catch {
              // Hosting diagnostics are deliberately non-authoritative and must not replace the
              // categorical lifecycle state or expose their original error through this boundary.
            }
          }
        } finally {
          inFlight = undefined;
        }
        return current();
      })();
      return inFlight;
    },
    resume() {
      if (inFlight || state === "draining") {
        throw new Error("GitHub App service stop attempt is still in progress.");
      }
      if (state === "ready-to-stop") {
        throw new Error("GitHub App service lifecycle is already ready to stop and cannot be resumed.");
      }
      if (state === "stop-failed") options.maintenance.resumeAdmission();
      state = "running";
      reason = undefined;
      return current();
    },
  };

  return controller;
}

/**
 * Bind SIGTERM/SIGINT to the lifecycle controller without calling process.exit() or stopping a
 * service directly. The trusted onReadyToStop callback remains the only handoff into hosting code.
 */
export function bindSynSecGitHubAppServiceSignals(
  controller: SynSecGitHubAppServiceLifecycleController,
  source: SynSecGitHubAppSignalSource = process,
): SynSecGitHubAppSignalBinding {
  if (!controller || typeof controller.requestStop !== "function") {
    throw new Error("GitHub App service lifecycle controller is required.");
  }
  if (!source || typeof source.on !== "function" || typeof source.off !== "function") {
    throw new Error("GitHub App signal source must provide on/off methods.");
  }

  const onSigterm = (): void => { void controller.requestStop("SIGTERM"); };
  const onSigint = (): void => { void controller.requestStop("SIGINT"); };
  source.on("SIGTERM", onSigterm);
  source.on("SIGINT", onSigint);
  let disposed = false;

  return {
    dispose() {
      if (disposed) return;
      disposed = true;
      source.off("SIGTERM", onSigterm);
      source.off("SIGINT", onSigint);
    },
  };
}
