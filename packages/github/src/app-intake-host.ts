import type { GitHubAppRuntimeCredentialSnapshot, GitHubAppRuntimeCredentialStatus } from "./runtime-credentials.js";
import { createGitHubAppRuntimeCredentialSource } from "./runtime-credentials.js";
import { loadMountedGitHubAppRuntimeCredentialSnapshot } from "./mounted-runtime-credentials.js";
import { parseGitHubAppHostProfile, type NormalizedGitHubAppHostProfile } from "./app-host-profile.js";
import { createSynSecGitHubAppDrainController, type SynSecGitHubAppDrainController } from "./app-drain.js";
import { createGitHubAppWebhookHttpHandler } from "./app-http.js";
import {
  createGitHubAppServer,
  type GitHubAppServer,
  type GitHubAppServerAddress,
  type GitHubAppServerTlsOptions,
} from "./app-server.js";
import {
  buildSynSecGitHubPostgresBackendContract,
  createSynSecGitHubPostgresSharedStores,
  migrateSynSecGitHubPostgresBackend,
} from "./postgres-shared-backend.js";
import type { PostgresPoolLike, PostgresGitHubSharedStateOptions } from "./postgres-shared-state.js";
import { assessGitHubAppSharedStateConformanceEvidence } from "./shared-state-evidence.js";

export interface SynSecGitHubAppIntakeHostOptions {
  /** Exact-keyed non-secret deployment profile. */
  profile: unknown;
  /** Caller-owned PostgreSQL pool. Connection material never enters the profile or returned status. */
  pool: PostgresPoolLike;
  /** Portable report produced by the real-backend canonical conformance suite for this adapter build. */
  conformanceReport: unknown;
  /** Optional local TLS material owned by the trusted hosting process. */
  tls?: GitHubAppServerTlsOptions;
  /** Optional shared-state tuning; bounded by the concrete PostgreSQL stores. */
  sharedStateOptions?: PostgresGitHubSharedStateOptions;
  webhookPath?: string;
  onWebhookError?: (error: Error) => void;
  /** Test/hosting seam. Defaults to the fixed-filename mounted credential loader. */
  loadCredentials?: () => Promise<GitHubAppRuntimeCredentialSnapshot>;
}

export interface SynSecGitHubAppIntakeHost {
  readonly profile: NormalizedGitHubAppHostProfile;
  readonly server: GitHubAppServer;
  readonly drain: SynSecGitHubAppDrainController;
  readonly interpretation: "executable-intake-host-boundary-not-worker-or-fleet-readiness";
  credentialStatus(): GitHubAppRuntimeCredentialStatus;
  reloadCredentials(): Promise<GitHubAppRuntimeCredentialStatus>;
  start(): Promise<GitHubAppServerAddress>;
  /** Close webhook admission, wait for locally admitted webhook requests, then close the listener. */
  close(timeoutMs?: number): Promise<void>;
}

function categoricalWebhookError(callback: ((error: Error) => void) | undefined): ((error: unknown) => void) | undefined {
  if (!callback) return undefined;
  return () => callback(new Error("GitHub App webhook processing failed."));
}

/**
 * Compose SynSec's concrete PostgreSQL webhook intake path into one executable host boundary.
 *
 * Activation fails closed before credential loading or database migration unless the supplied
 * canonical conformance report is complete and bound to this exact built-in PostgreSQL adapter
 * id/version. Credentials are then loaded from the operator-owned mounted source into the existing
 * memory-only atomic generation, migrations run through the serialized PostgreSQL migration path,
 * and webhook intake is wrapped by the enforced local admission-drain controller before the bounded
 * HTTP(S) listener is created.
 *
 * This host intentionally does not run scanner workers, ownership sweeps, or service-manager logic.
 * A listening intake process therefore proves neither fleet readiness nor scan completion. Worker
 * deployments must independently use the durable fenced queue and their own lifecycle/drain gates.
 */
export async function createSynSecGitHubAppIntakeHost(
  options: SynSecGitHubAppIntakeHostOptions,
): Promise<SynSecGitHubAppIntakeHost> {
  if (!options || typeof options !== "object") throw new Error("GitHub App intake host options are required.");
  const profile = parseGitHubAppHostProfile(options.profile);

  const contract = buildSynSecGitHubPostgresBackendContract();
  const evidence = assessGitHubAppSharedStateConformanceEvidence(contract, options.conformanceReport);
  if (!evidence.ready) {
    throw new Error(`GitHub App intake host shared-state evidence is not ready: ${evidence.issues.map((issue) => issue.code).join(", ")}`);
  }

  if (profile.tlsMode === "local" && (!options.tls?.key || !options.tls.cert)) {
    throw new Error("GitHub App intake host local TLS requires caller-owned key and certificate material.");
  }
  if (profile.tlsMode !== "local" && options.tls !== undefined) {
    throw new Error("GitHub App intake host TLS material is accepted only for local TLS mode.");
  }

  const loadCredentials = options.loadCredentials
    ?? (() => loadMountedGitHubAppRuntimeCredentialSnapshot(profile.credentialDirectory));
  const credentialSource = createGitHubAppRuntimeCredentialSource(await loadCredentials());

  await migrateSynSecGitHubPostgresBackend(options.pool);
  const stores = createSynSecGitHubPostgresSharedStores(options.pool, options.sharedStateOptions);
  const rawWebhookHandler = createGitHubAppWebhookHttpHandler({
    webhookSecret: () => credentialSource.getWebhookSecret(),
    replayStore: stores.replayStore,
    installationStore: stores.installationStore,
    queue: stores.queue,
    ...(options.webhookPath ? { path: options.webhookPath } : {}),
    ...(categoricalWebhookError(options.onWebhookError)
      ? { onError: categoricalWebhookError(options.onWebhookError) }
      : {}),
  });
  const drain = createSynSecGitHubAppDrainController(rawWebhookHandler);
  const server = createGitHubAppServer({
    host: profile.listenHost,
    port: profile.port,
    tlsMode: profile.tlsMode,
    webhookHandler: drain.webhookHandler,
    ...(profile.tlsMode === "local" && options.tls ? { tls: options.tls } : {}),
  });

  return {
    profile,
    server,
    drain,
    interpretation: "executable-intake-host-boundary-not-worker-or-fleet-readiness",
    credentialStatus: () => credentialSource.getStatus(),
    reloadCredentials: () => credentialSource.reload(loadCredentials),
    start: () => server.start(),
    async close(timeoutMs?: number): Promise<void> {
      drain.beginDrain();
      await drain.waitForDrained(timeoutMs);
      await server.close();
    },
  };
}
