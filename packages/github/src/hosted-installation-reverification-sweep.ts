import type {
  SynSecGitHubUserInstallationTransport,
  SynSecHostedGitHubPrincipal,
} from "./hosted-installation-ownership.js";
import {
  reverifySynSecHostedGitHubInstallation,
  type SynSecHostedInstallationReverificationStore,
} from "./hosted-installation-reverification.js";

const MAX_IDENTIFIER_LENGTH = 128;
const MAX_TARGETS = 10_000;
const DEFAULT_CONCURRENCY = 4;
const MIN_CONCURRENCY = 1;
const MAX_CONCURRENCY = 32;

export interface SynSecHostedInstallationReverificationTarget {
  principal: SynSecHostedGitHubPrincipal;
  installationId: number;
}

/**
 * Hosting-owned target and credential boundary.
 *
 * listTargets() must derive targets from trusted hosted tenant state rather than repository input.
 * createTransport() owns user-scoped GitHub credentials and should return a freshly usable bounded
 * transport for only the target being processed. SynSec does not persist or serialize that transport.
 */
export interface SynSecHostedInstallationReverificationTargetProvider {
  listTargets(): Promise<readonly SynSecHostedInstallationReverificationTarget[]>;
  createTransport(
    target: SynSecHostedInstallationReverificationTarget,
  ): Promise<SynSecGitHubUserInstallationTransport> | SynSecGitHubUserInstallationTransport;
}

export interface SynSecHostedInstallationReverificationSweepResult {
  status: "completed";
  attempted: number;
  verified: number;
  revoked: number;
  superseded: number;
  failed: number;
  interpretation: "scheduler-observation-only-not-authorization-evidence";
}

export interface SynSecHostedInstallationReverificationSweepOptions {
  provider: SynSecHostedInstallationReverificationTargetProvider;
  store: SynSecHostedInstallationReverificationStore;
  concurrency?: number;
}

export interface SynSecHostedInstallationReverificationSweepStatus {
  active: boolean;
  completedSweeps: number;
  lastResult?: SynSecHostedInstallationReverificationSweepResult;
  interpretation: "process-local-scheduler-status-only";
}

function boundedIdentifier(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} must be a string.`);
  const normalized = value.trim();
  if (!normalized
    || normalized.length > MAX_IDENTIFIER_LENGTH
    || !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(normalized)) {
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

function concurrency(value: number | undefined): number {
  const resolved = value ?? DEFAULT_CONCURRENCY;
  if (!Number.isSafeInteger(resolved) || resolved < MIN_CONCURRENCY || resolved > MAX_CONCURRENCY) {
    throw new Error(`Hosted installation re-verification concurrency must be between ${MIN_CONCURRENCY} and ${MAX_CONCURRENCY}.`);
  }
  return resolved;
}

function validatedTarget(
  value: SynSecHostedInstallationReverificationTarget,
): SynSecHostedInstallationReverificationTarget {
  if (!value || typeof value !== "object") throw new Error("Hosted installation re-verification target is invalid.");
  if (!value.principal || typeof value.principal !== "object") {
    throw new Error("Hosted installation re-verification target principal is invalid.");
  }
  return {
    principal: {
      subject: boundedIdentifier(value.principal.subject, "Hosted principal subject"),
      tenantId: boundedIdentifier(value.principal.tenantId, "Hosted tenant id"),
      githubUserId: positiveInteger(value.principal.githubUserId, "Authenticated GitHub user id"),
    },
    installationId: positiveInteger(value.installationId, "GitHub installation id"),
  };
}

function validateOptions(options: SynSecHostedInstallationReverificationSweepOptions): number {
  if (!options || typeof options !== "object") {
    throw new Error("Hosted installation re-verification sweep options are required.");
  }
  if (!options.provider
    || typeof options.provider.listTargets !== "function"
    || typeof options.provider.createTransport !== "function") {
    throw new Error("Hosted installation re-verification target provider is required.");
  }
  if (!options.store
    || typeof options.store.beginReverification !== "function"
    || typeof options.store.finishVerified !== "function"
    || typeof options.store.finishRevoked !== "function"
    || typeof options.store.isFreshlyAuthorized !== "function") {
    throw new Error("Hosted installation re-verification store is required.");
  }
  return concurrency(options.concurrency);
}

async function loadTargets(
  provider: SynSecHostedInstallationReverificationTargetProvider,
): Promise<SynSecHostedInstallationReverificationTarget[]> {
  let values: readonly SynSecHostedInstallationReverificationTarget[];
  try {
    values = await provider.listTargets();
  } catch {
    throw new Error("Hosted installation re-verification target discovery failed.");
  }
  if (!Array.isArray(values)) throw new Error("Hosted installation re-verification target discovery returned an invalid result.");
  if (values.length > MAX_TARGETS) {
    throw new Error(`Hosted installation re-verification sweep exceeds the ${MAX_TARGETS}-target limit.`);
  }

  const targets = values.map(validatedTarget);
  const identities = new Set<string>();
  for (const target of targets) {
    const identity = `${target.principal.tenantId}\u0000${target.installationId}`;
    if (identities.has(identity)) {
      throw new Error("Hosted installation re-verification targets contain a duplicate tenant installation.");
    }
    identities.add(identity);
  }
  return targets;
}

/**
 * Execute one bounded periodic ownership re-verification sweep.
 *
 * This function deliberately returns aggregate observations only. A completed sweep, successful
 * scheduler invocation, or zero failures is not authorization evidence. Hosted request paths must
 * continue to call the durable freshness gate before granting installation-scoped access.
 *
 * The transport boundary owns HTTP timeouts/cancellation. This function does not simulate timeout by
 * abandoning an in-flight remote call because that call could still complete a fenced durable write.
 */
export async function runSynSecHostedInstallationReverificationSweep(
  options: SynSecHostedInstallationReverificationSweepOptions,
): Promise<SynSecHostedInstallationReverificationSweepResult> {
  const limit = validateOptions(options);
  const targets = await loadTargets(options.provider);
  let cursor = 0;
  const counters = {
    verified: 0,
    revoked: 0,
    superseded: 0,
    failed: 0,
  };

  async function worker(): Promise<void> {
    while (true) {
      const index = cursor;
      cursor += 1;
      if (index >= targets.length) return;
      const target = targets[index];
      if (!target) return;
      try {
        const transport = await options.provider.createTransport(target);
        if (!transport
          || typeof transport.getAuthenticatedUser !== "function"
          || typeof transport.getAccessibleInstallation !== "function") {
          throw new Error("invalid transport");
        }
        const evidence = await reverifySynSecHostedGitHubInstallation({
          principal: target.principal,
          installationId: target.installationId,
          transport,
          store: options.store,
        });
        counters[evidence.status] += 1;
      } catch {
        counters.failed += 1;
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(limit, Math.max(1, targets.length)) }, () => worker()));
  return {
    status: "completed",
    attempted: targets.length,
    ...counters,
    interpretation: "scheduler-observation-only-not-authorization-evidence",
  };
}

/**
 * Process-local overlap coalescing for service-manager timers or embedded schedulers.
 *
 * Multi-replica safety still comes from the durable verification epoch, not this object. Different
 * replicas may run simultaneously; this controller merely avoids duplicate sweeps inside one process.
 */
export class SynSecHostedInstallationReverificationSweepController {
  private inFlight: Promise<SynSecHostedInstallationReverificationSweepResult> | undefined;
  private completedSweeps = 0;
  private lastResult: SynSecHostedInstallationReverificationSweepResult | undefined;

  constructor(private readonly options: SynSecHostedInstallationReverificationSweepOptions) {
    validateOptions(options);
  }

  runOnce(): Promise<SynSecHostedInstallationReverificationSweepResult> {
    if (this.inFlight) return this.inFlight;
    const operation = runSynSecHostedInstallationReverificationSweep(this.options)
      .then((result) => {
        this.completedSweeps += 1;
        this.lastResult = result;
        return result;
      })
      .finally(() => {
        if (this.inFlight === operation) this.inFlight = undefined;
      });
    this.inFlight = operation;
    return operation;
  }

  status(): SynSecHostedInstallationReverificationSweepStatus {
    return {
      active: this.inFlight !== undefined,
      completedSweeps: this.completedSweeps,
      ...(this.lastResult ? { lastResult: { ...this.lastResult } } : {}),
      interpretation: "process-local-scheduler-status-only",
    };
  }
}
