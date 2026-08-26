import type { SynSecConfig } from "@synsec/config";
import { runScanEngine } from "@synsec/engine";
import {
  createOciIsolatedScanners,
  withBuiltInScannerFactory,
} from "@synsec/scanners";
import { parseGitHubAppHostProfile, type NormalizedGitHubAppHostProfile } from "./app-host-profile.js";
import { createSynSecGitHubAppWorkerDrainController, type SynSecGitHubAppWorkerDrainController } from "./app-worker-drain.js";
import {
  runConfiguredGitHubAppWorkerOnce,
  type ConfiguredGitHubAppWorkerResult,
} from "./app-worker-runner.js";
import { createGitHubAppInstallationTokenProvider } from "./app-token-provider.js";
import { createGitHubAppRuntimeCredentialSource, type GitHubAppRuntimeCredentialSnapshot, type GitHubAppRuntimeCredentialStatus } from "./runtime-credentials.js";
import { loadMountedGitHubAppRuntimeCredentialSnapshot } from "./mounted-runtime-credentials.js";
import {
  buildSynSecGitHubPostgresBackendContract,
  createSynSecGitHubPostgresSharedStores,
  migrateSynSecGitHubPostgresBackend,
} from "./postgres-shared-backend.js";
import type { PostgresGitHubSharedStateOptions, PostgresPoolLike } from "./postgres-shared-state.js";
import { assessGitHubAppSharedStateConformanceEvidence } from "./shared-state-evidence.js";

const OCI_WORKER_SCANNERS = new Set(["checkov", "grype", "syft"]);

export interface SynSecGitHubAppWorkerHostOptions {
  /** Exact-keyed non-secret deployment profile shared with the intake role. */
  profile: unknown;
  /** Caller-owned PostgreSQL pool. Connection material never enters returned status. */
  pool: PostgresPoolLike;
  /** Canonical real-backend conformance report bound to the exact built-in PostgreSQL adapter. */
  conformanceReport: unknown;
  /** Trusted worker scan configuration. Hosted OCI workers currently accept Checkov, Grype, and Syft. */
  config: SynSecConfig;
  sharedStateOptions?: PostgresGitHubSharedStateOptions;
  publishSarif?: boolean;
  toolVersion?: string;
  apiVersion?: string;
  userAgent?: string;
  fetch?: typeof globalThis.fetch;
  /** Test/hosting seam. Defaults to the fixed-filename mounted credential loader. */
  loadCredentials?: () => Promise<GitHubAppRuntimeCredentialSnapshot>;
}

export interface SynSecGitHubAppWorkerHost {
  readonly profile: NormalizedGitHubAppHostProfile;
  readonly drain: SynSecGitHubAppWorkerDrainController;
  readonly interpretation: "executable-fenced-worker-with-enforced-oci-subset-not-fleet-readiness-or-complete-coverage";
  credentialStatus(): GitHubAppRuntimeCredentialStatus;
  reloadCredentials(): Promise<GitHubAppRuntimeCredentialStatus>;
  runOnce(): Promise<ConfiguredGitHubAppWorkerResult>;
  beginDrain(): void;
  resumeAdmission(): void;
  close(timeoutMs?: number): Promise<void>;
}

/**
 * Validate the scanner set that the executable hosted worker can truthfully isolate today.
 *
 * The current enforced OCI integration supports Checkov, Grype, and Syft because all three adapters
 * accept the sandbox process runner for availability checks and scan execution. Rejecting every other
 * selected scanner is intentional: the worker must never silently fall back to host execution merely
 * to gain scanner breadth. AI review is likewise disabled in this role because it is a separate
 * outbound trust boundary and is not part of the scanner sandbox contract.
 */
export function assertGitHubAppOciWorkerConfig(config: SynSecConfig): void {
  if (!config || config.schemaVersion !== 1 || !Array.isArray(config.scanners)) {
    throw new Error("GitHub App OCI worker requires a valid SynSec configuration.");
  }
  if (config.scanners.length === 0) throw new Error("GitHub App OCI worker requires at least one isolated scanner.");
  const selected = new Set<string>();
  for (const scanner of config.scanners) {
    if (typeof scanner !== "string" || !OCI_WORKER_SCANNERS.has(scanner)) {
      throw new Error("GitHub App OCI worker configuration contains a scanner without enforced hosted isolation support.");
    }
    if (selected.has(scanner)) throw new Error("GitHub App OCI worker configuration contains duplicate scanner ids.");
    selected.add(scanner);
  }
  if (config.ai?.enabled) {
    throw new Error("GitHub App OCI worker does not enable AI review inside the scanner-isolation role.");
  }
}

/**
 * Compose one production worker replica around the durable PostgreSQL queue and enforced OCI subset.
 *
 * Activation order is fail-closed: validate the secret-free profile and worker scanner policy, verify
 * exact canonical PostgreSQL conformance evidence, then load credentials, then migrate/construct the
 * durable stores. Each run enters the worker-drain admission boundary before queue.claimNext(). The
 * normal worker then owns the durable lease heartbeat/fence, rechecks installation authorization,
 * acquires exact commits with a short-lived installation token, and obtains a fresh publication token.
 *
 * Scanner availability and scan execution run under an AsyncLocalStorage-scoped factory containing
 * only digest-pinned OCI adapters rooted at the acquired repository. The sandbox itself enforces
 * network=none, read-only repository/root filesystems, separate tmpfs scratch, non-root execution,
 * dropped capabilities, no-new-privileges, and bounded CPU/memory/PIDs. GitHub credentials stay in
 * the host acquisition/publication layers and are never supplied as scanner environment variables.
 *
 * This role intentionally rejects unsupported scanner ids rather than falling back to host execution.
 * Therefore successful execution is evidence for the enforced Checkov/Grype/Syft worker path only,
 * not proof of complete scanner coverage, fleet readiness, runtime exploitability, or absence of vulnerabilities.
 */
export async function createSynSecGitHubAppWorkerHost(
  options: SynSecGitHubAppWorkerHostOptions,
): Promise<SynSecGitHubAppWorkerHost> {
  if (!options || typeof options !== "object") throw new Error("GitHub App worker host options are required.");
  const profile = parseGitHubAppHostProfile(options.profile);
  assertGitHubAppOciWorkerConfig(options.config);

  const contract = buildSynSecGitHubPostgresBackendContract();
  const evidence = assessGitHubAppSharedStateConformanceEvidence(contract, options.conformanceReport);
  if (!evidence.ready) {
    throw new Error(`GitHub App worker host shared-state evidence is not ready: ${evidence.issues.map((issue) => issue.code).join(", ")}`);
  }

  const loadCredentials = options.loadCredentials
    ?? (() => loadMountedGitHubAppRuntimeCredentialSnapshot(profile.credentialDirectory));
  const credentialSource = createGitHubAppRuntimeCredentialSource(await loadCredentials());

  await migrateSynSecGitHubPostgresBackend(options.pool);
  const stores = createSynSecGitHubPostgresSharedStores(options.pool, options.sharedStateOptions);
  const drain = createSynSecGitHubAppWorkerDrainController();
  const getInstallationToken = createGitHubAppInstallationTokenProvider({
    appId: profile.appId,
    privateKey: () => credentialSource.getPrivateKey(),
    ...(options.apiVersion ? { apiVersion: options.apiVersion } : {}),
    ...(options.userAgent ? { userAgent: options.userAgent } : {}),
    ...(options.fetch ? { fetch: options.fetch } : {}),
    requiredPermissionsByPurpose: {
      acquire: { contents: "read" },
      publish: {
        checks: "write",
        ...(options.publishSarif ? { security_events: "write" as const } : {}),
      },
    },
  });

  const scan = async (input: Parameters<typeof runScanEngine>[0]) => withBuiltInScannerFactory(
    () => createOciIsolatedScanners({
      runtimeCommand: profile.scannerRuntimeCommand,
      image: profile.scannerImage,
      repositoryRoot: input.rootPath,
    }),
    () => runScanEngine(input),
  );

  return {
    profile,
    drain,
    interpretation: "executable-fenced-worker-with-enforced-oci-subset-not-fleet-readiness-or-complete-coverage",
    credentialStatus: () => credentialSource.getStatus(),
    reloadCredentials: () => credentialSource.reload(loadCredentials),
    runOnce: () => runConfiguredGitHubAppWorkerOnce({
      queue: stores.queue,
      installationStore: stores.installationStore,
      config: options.config,
      getInstallationToken: (installationId, purpose) => getInstallationToken(installationId, purpose),
      workerDrain: drain,
      scan,
      publishSarif: options.publishSarif,
      toolVersion: options.toolVersion,
      acquisitionOptions: { workspaceRoot: profile.workspaceDirectory },
      ...(options.apiVersion ? { apiVersion: options.apiVersion } : {}),
      ...(options.userAgent ? { userAgent: options.userAgent } : {}),
      ...(options.fetch ? { fetch: options.fetch } : {}),
    }),
    beginDrain() {
      drain.beginDrain();
    },
    resumeAdmission() {
      drain.resumeAdmission();
    },
    async close(timeoutMs?: number): Promise<void> {
      drain.beginDrain();
      await drain.waitForDrained(timeoutMs);
    },
  };
}
