import type { FindingLifecycleStore, FindingState } from "./index.js";

const DEFAULT_DUE_SOON_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_DUE_SOON_MS = 365 * 24 * 60 * 60 * 1000;

export type LifecycleReviewDeadlineStatus = "overdue" | "due-soon" | "scheduled";

export interface LifecycleReviewDeadlineItem {
  fingerprint: string;
  state: FindingState;
  reviewAt: string;
  status: LifecycleReviewDeadlineStatus;
}

export interface LifecycleReviewDeadlineAssessment {
  schemaVersion: 1;
  generatedAt: string;
  dueSoonWindowMs: number;
  items: LifecycleReviewDeadlineItem[];
  summary: {
    reviewable: number;
    unscheduled: number;
    overdue: number;
    dueSoon: number;
    scheduled: number;
  };
}

function reviewableState(state: FindingState): boolean {
  return state === "accepted-risk" || state === "false-positive";
}

/**
 * Assess governance re-review deadlines for active exception decisions.
 *
 * Only accepted-risk and false-positive records are reviewable here. Scanner-derived states are not
 * modified, no lifecycle records are written, and notes/owners/report ids/source paths are excluded
 * from the returned artifact. Missing review deadlines are reported separately so an operator can
 * distinguish an overdue exception from one that has never been scheduled for re-review.
 */
export function assessLifecycleReviewDeadlines(
  store: FindingLifecycleStore,
  options: { now?: string; dueSoonWindowMs?: number } = {},
): LifecycleReviewDeadlineAssessment {
  const nowText = options.now ?? new Date().toISOString();
  const now = Date.parse(nowText);
  if (!Number.isFinite(now)) throw new Error("Lifecycle review assessment time must be a valid timestamp.");

  const dueSoonWindowMs = options.dueSoonWindowMs ?? DEFAULT_DUE_SOON_MS;
  if (!Number.isSafeInteger(dueSoonWindowMs) || dueSoonWindowMs < 0 || dueSoonWindowMs > MAX_DUE_SOON_MS) {
    throw new Error(`Lifecycle review due-soon window must be an integer between 0 and ${MAX_DUE_SOON_MS} milliseconds.`);
  }

  let reviewable = 0;
  let unscheduled = 0;
  const items: LifecycleReviewDeadlineItem[] = [];

  for (const record of Object.values(store.records)) {
    if (!reviewableState(record.state)) continue;
    reviewable += 1;
    if (!record.reviewAt) {
      unscheduled += 1;
      continue;
    }

    const reviewAt = Date.parse(record.reviewAt);
    if (!Number.isFinite(reviewAt)) {
      throw new Error("Lifecycle review assessment encountered an invalid review deadline.");
    }
    const status: LifecycleReviewDeadlineStatus = reviewAt <= now
      ? "overdue"
      : reviewAt - now <= dueSoonWindowMs
        ? "due-soon"
        : "scheduled";
    items.push({
      fingerprint: record.fingerprint,
      state: record.state,
      reviewAt: record.reviewAt,
      status,
    });
  }

  items.sort((a, b) => {
    const byTime = Date.parse(a.reviewAt) - Date.parse(b.reviewAt);
    return byTime !== 0 ? byTime : a.fingerprint.localeCompare(b.fingerprint);
  });

  return {
    schemaVersion: 1,
    generatedAt: new Date(now).toISOString(),
    dueSoonWindowMs,
    items,
    summary: {
      reviewable,
      unscheduled,
      overdue: items.filter((item) => item.status === "overdue").length,
      dueSoon: items.filter((item) => item.status === "due-soon").length,
      scheduled: items.filter((item) => item.status === "scheduled").length,
    },
  };
}
