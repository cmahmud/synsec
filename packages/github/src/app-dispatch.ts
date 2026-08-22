import type { GitHubAppWebhookIntakeResult } from "./app-intake.js";
import type { GitHubScanJob, GitHubScanJobInput } from "./scan-queue.js";

export interface GitHubInstallationAuthorizer {
  isRepositoryAllowed(installationId: number, repository: string): Promise<boolean>;
}

export interface GitHubScanJobEnqueuer {
  enqueue(input: GitHubScanJobInput): Promise<GitHubScanJob>;
}

export type GitHubAppDispatchResult =
  | { status: "ignored"; reason: "duplicate" | "non_scan_event" }
  | { status: "rejected"; reason: "installation_not_authorized" }
  | { status: "queued"; job: GitHubScanJob };

/**
 * Apply the final hosted-App authorization gate before durable queueing.
 *
 * This function consumes only a verified/deduplicated intake result. It never follows
 * payload URLs and requires durable installation state to authorize the normalized
 * owner/name repository before constructing a commit-pinned queue descriptor.
 */
export async function dispatchGitHubAppWebhookScan(input: {
  intake: GitHubAppWebhookIntakeResult;
  installationStore: GitHubInstallationAuthorizer;
  queue: GitHubScanJobEnqueuer;
}): Promise<GitHubAppDispatchResult> {
  const { intake } = input;
  if (intake.duplicate) return { status: "ignored", reason: "duplicate" };
  if (!intake.shouldScan) return { status: "ignored", reason: "non_scan_event" };

  const webhook = intake.webhook;
  if (!webhook.installationId || !webhook.repository || !webhook.headSha || !webhook.deliveryId) {
    throw new Error("Scan-eligible GitHub App webhook is missing normalized queue identity.");
  }
  if (!await input.installationStore.isRepositoryAllowed(webhook.installationId, webhook.repository)) {
    return { status: "rejected", reason: "installation_not_authorized" };
  }

  if (webhook.event === "pull_request") {
    if (!webhook.baseSha || !webhook.pullRequestNumber) {
      throw new Error("Scan-eligible pull request webhook is missing base commit or pull request identity.");
    }
    const job = await input.queue.enqueue({
      deliveryId: webhook.deliveryId,
      installationId: webhook.installationId,
      repository: webhook.repository,
      headSha: webhook.headSha,
      event: "pull_request",
      baseSha: webhook.baseSha,
      pullRequestNumber: webhook.pullRequestNumber,
    });
    return { status: "queued", job };
  }

  if (webhook.event !== "push") {
    throw new Error("Only push and pull_request webhooks may reach scan dispatch.");
  }
  const job = await input.queue.enqueue({
    deliveryId: webhook.deliveryId,
    installationId: webhook.installationId,
    repository: webhook.repository,
    headSha: webhook.headSha,
    event: "push",
  });
  return { status: "queued", job };
}
