import {
  parseVerifiedGitHubAppWebhook,
  shouldScanGitHubAppWebhook,
  type GitHubAppWebhook,
} from "./app.js";

export interface GitHubWebhookReplayClaimer {
  claim(deliveryId: string): Promise<{ accepted: boolean; deliveryId: string; receivedAt: string }>;
}

export interface GitHubAppWebhookIntakeResult {
  webhook: GitHubAppWebhook;
  duplicate: boolean;
  shouldScan: boolean;
}

/**
 * Verify, normalize, deduplicate, and classify one GitHub App webhook delivery.
 *
 * Signature verification intentionally happens before the durable replay claim so
 * unauthenticated traffic cannot fill the replay store. A duplicate authenticated
 * delivery is returned for idempotent HTTP handling but is never scan-eligible.
 */
export async function intakeGitHubAppWebhook(input: {
  body: string | Uint8Array;
  signatureHeader?: string;
  webhookSecret: string;
  eventName: string;
  deliveryId: string;
  replayStore: GitHubWebhookReplayClaimer;
}): Promise<GitHubAppWebhookIntakeResult> {
  const deliveryId = input.deliveryId.trim();
  if (!deliveryId) throw new Error("GitHub webhook delivery id is required for replay protection.");

  const webhook = parseVerifiedGitHubAppWebhook({
    body: input.body,
    signatureHeader: input.signatureHeader,
    webhookSecret: input.webhookSecret,
    eventName: input.eventName,
    deliveryId,
  });

  const claim = await input.replayStore.claim(deliveryId);
  if (claim.deliveryId !== deliveryId) {
    throw new Error("Webhook replay store returned a mismatched delivery id.");
  }

  const duplicate = !claim.accepted;
  return {
    webhook,
    duplicate,
    shouldScan: !duplicate && shouldScanGitHubAppWebhook(webhook),
  };
}
