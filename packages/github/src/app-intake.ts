import { sanitizeOperationalText } from "@synsec/scanner-sdk";
import {
  parseVerifiedGitHubAppWebhook,
  shouldScanGitHubAppWebhook,
  type GitHubAppWebhook,
  type GitHubWebhookSecret,
} from "./app.js";

export interface GitHubWebhookReplayClaimer {
  claim(deliveryId: string): Promise<{ accepted: boolean; deliveryId: string; receivedAt: string }>;
}

export interface GitHubAppWebhookIntakeResult {
  webhook: GitHubAppWebhook;
  duplicate: boolean;
  shouldScan: boolean;
  replayReceivedAt: string;
}

function safeReplayError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return sanitizeOperationalText(message, 1000) || "Webhook replay claim failed.";
}

/**
 * Verify, normalize, deduplicate, and classify one GitHub App webhook delivery.
 *
 * Signature verification intentionally happens before the durable replay claim so
 * unauthenticated traffic cannot fill the replay store. A duplicate authenticated
 * delivery is returned for idempotent HTTP handling but is never scan-eligible.
 * The accepted claim timestamp is retained so a higher-level handler can release
 * exactly that claim if downstream durable processing fails. Replay-backend failures
 * are sanitized before crossing the intake boundary so connection credentials cannot
 * be forwarded into hosted logging/error hooks.
 */
export async function intakeGitHubAppWebhook(input: {
  body: string | Uint8Array;
  signatureHeader?: string;
  webhookSecret: GitHubWebhookSecret;
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

  let claim: Awaited<ReturnType<GitHubWebhookReplayClaimer["claim"]>>;
  try {
    claim = await input.replayStore.claim(deliveryId);
  } catch (error) {
    throw new Error(safeReplayError(error));
  }
  if (claim.deliveryId !== deliveryId) {
    throw new Error("Webhook replay store returned a mismatched delivery id.");
  }

  const duplicate = !claim.accepted;
  return {
    webhook,
    duplicate,
    shouldScan: !duplicate && shouldScanGitHubAppWebhook(webhook),
    replayReceivedAt: claim.receivedAt,
  };
}
