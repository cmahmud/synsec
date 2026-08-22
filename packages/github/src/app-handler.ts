import {
  intakeGitHubAppWebhook,
  type GitHubWebhookReplayClaimer,
} from "./app-intake.js";
import {
  dispatchGitHubAppWebhookScan,
  type GitHubScanJobEnqueuer,
} from "./app-dispatch.js";
import {
  synchronizeVerifiedGitHubInstallationWebhook,
  type GitHubInstallationStateStore,
} from "./installation-sync.js";
import type { GitHubScanJob } from "./scan-queue.js";

export interface GitHubAppInstallationStore extends GitHubInstallationStateStore {
  isRepositoryAllowed(installationId: number, repository: string): Promise<boolean>;
}

export interface GitHubWebhookReplayManager extends GitHubWebhookReplayClaimer {
  release(deliveryId: string, receivedAt: string): Promise<boolean>;
}

export type GitHubAppWebhookHandleResult =
  | { status: "ignored"; reason: "duplicate" | "non_scan_event" }
  | { status: "rejected"; reason: "installation_not_authorized" }
  | { status: "queued"; job: GitHubScanJob }
  | { status: "installation_updated"; installationId: number }
  | { status: "installation_removed"; installationId: number; existed: boolean };

function safeError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.replace(/[\r\n]+/g, " ").trim().slice(0, 1000) || "unknown replay-store error";
}

/**
 * Execute the durable hosted-App intake boundary for one webhook delivery.
 *
 * The order is deliberate: verify/normalize -> replay claim -> installation bookkeeping
 * or authorization-gated scan dispatch. Duplicate authenticated deliveries never mutate
 * installation state or enqueue work. Installation-management events never trigger scans.
 * If durable processing fails after an accepted replay claim, that exact unexpired claim is
 * released before the error is propagated so GitHub can retry rather than losing the delivery.
 */
export async function handleGitHubAppWebhook(input: {
  body: string | Uint8Array;
  signatureHeader?: string;
  webhookSecret: string;
  eventName: string;
  deliveryId: string;
  replayStore: GitHubWebhookReplayManager;
  installationStore: GitHubAppInstallationStore;
  queue: GitHubScanJobEnqueuer;
  now?: number;
}): Promise<GitHubAppWebhookHandleResult> {
  const deliveryId = input.deliveryId.trim();
  const intake = await intakeGitHubAppWebhook({
    body: input.body,
    signatureHeader: input.signatureHeader,
    webhookSecret: input.webhookSecret,
    eventName: input.eventName,
    deliveryId,
    replayStore: input.replayStore,
  });

  if (intake.duplicate) return { status: "ignored", reason: "duplicate" };

  try {
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

    return await dispatchGitHubAppWebhookScan({
      intake,
      installationStore: input.installationStore,
      queue: input.queue,
    });
  } catch (error) {
    let released: boolean;
    try {
      released = await input.replayStore.release(deliveryId, intake.replayReceivedAt);
    } catch (releaseError) {
      throw new Error(`${safeError(error)} Replay claim release failed: ${safeError(releaseError)}`);
    }
    if (!released) {
      throw new Error(`${safeError(error)} Replay claim could not be released safely for retry.`);
    }
    throw error;
  }
}
