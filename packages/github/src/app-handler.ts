import {
  intakeGitHubAppWebhook,
  type GitHubWebhookReplayClaimer,
} from "./app-intake.js";
import {
  dispatchGitHubAppWebhookScan,
  type GitHubAppDispatchResult,
  type GitHubScanJobEnqueuer,
} from "./app-dispatch.js";
import {
  synchronizeVerifiedGitHubInstallationWebhook,
  type GitHubInstallationStateStore,
} from "./installation-sync.js";

export interface GitHubAppInstallationStore extends GitHubInstallationStateStore {
  isRepositoryAllowed(installationId: number, repository: string): Promise<boolean>;
}

export type GitHubAppWebhookHandleResult =
  | { status: "ignored"; reason: "duplicate" | "non_scan_event" }
  | { status: "rejected"; reason: "installation_not_authorized" }
  | { status: "queued"; job: GitHubAppDispatchResult extends { status: "queued"; job: infer Job } ? Job : never }
  | { status: "installation_updated"; installationId: number }
  | { status: "installation_removed"; installationId: number; existed: boolean };

/**
 * Execute the durable hosted-App intake boundary for one webhook delivery.
 *
 * The order is deliberate: verify/normalize -> replay claim -> installation bookkeeping
 * or authorization-gated scan dispatch. Duplicate authenticated deliveries never mutate
 * installation state or enqueue work. Installation-management events never trigger scans.
 */
export async function handleGitHubAppWebhook(input: {
  body: string | Uint8Array;
  signatureHeader?: string;
  webhookSecret: string;
  eventName: string;
  deliveryId: string;
  replayStore: GitHubWebhookReplayClaimer;
  installationStore: GitHubAppInstallationStore;
  queue: GitHubScanJobEnqueuer;
  now?: number;
}): Promise<GitHubAppWebhookHandleResult> {
  const intake = await intakeGitHubAppWebhook({
    body: input.body,
    signatureHeader: input.signatureHeader,
    webhookSecret: input.webhookSecret,
    eventName: input.eventName,
    deliveryId: input.deliveryId,
    replayStore: input.replayStore,
  });

  if (intake.duplicate) return { status: "ignored", reason: "duplicate" };

  if (intake.webhook.event === "installation" || intake.webhook.event === "installation_repositories") {
    const result = await synchronizeVerifiedGitHubInstallationWebhook({
      body: input.body,
      signatureHeader: input.signatureHeader,
      webhookSecret: input.webhookSecret,
      eventName: input.eventName,
      store: input.installationStore,
      ...(input.now !== undefined ? { now: input.now } : {}),
    });
    if (result.status === "removed") {
      return {
        status: "installation_removed",
        installationId: result.installationId,
        existed: result.existed,
      };
    }
    return { status: "installation_updated", installationId: result.record.installationId };
  }

  return dispatchGitHubAppWebhookScan({
    intake,
    installationStore: input.installationStore,
    queue: input.queue,
  });
}
