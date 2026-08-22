import type { SynSecReport } from "@synsec/report";
import type { FindingLifecycleStore, FindingState } from "./index.js";
import {
  commentsForFinding,
  type FindingReviewComment,
  type FindingReviewCommentStore,
} from "./review-comments.js";

export type FindingReviewDeadlineStatus = "scheduled" | "due";

export interface FindingTriageViewItem {
  fingerprint: string;
  title: string;
  severity: string;
  state: FindingState;
  updatedAt: string;
  owner?: string;
  note?: string;
  reviewAt?: string;
  /** Derived human-governance presentation state; never scanner evidence or a lifecycle transition. */
  reviewStatus?: FindingReviewDeadlineStatus;
  comments: FindingReviewComment[];
}

export interface FindingTriageView {
  schemaVersion: 1;
  reportId: string;
  items: FindingTriageViewItem[];
  summary: {
    current: number;
    assigned: number;
    unassigned: number;
    commented: number;
  };
  /** Triage view intentionally excludes source excerpts and scanner evidence. */
  interpretation: "triage-metadata-not-scanner-evidence";
}

function reviewDeadlineStatus(reviewAt: string | undefined, now: number): FindingReviewDeadlineStatus | undefined {
  if (!reviewAt) return undefined;
  return Date.parse(reviewAt) <= now ? "due" : "scheduled";
}

/**
 * Compose current finding lifecycle, ownership, re-review deadlines, and human review comments for UI/API presentation.
 *
 * Only findings present in the supplied report are returned. The view carries title/severity for
 * orientation plus bounded human triage metadata; source locations, source excerpts, scanner
 * diagnostics, artifacts, repository URLs, and finding metadata are deliberately not copied.
 * Review deadline status is derived presentation metadata only and never mutates lifecycle state.
 */
export function buildFindingTriageView(
  report: SynSecReport,
  lifecycle: FindingLifecycleStore,
  reviewComments: FindingReviewCommentStore,
  options: { now?: number } = {},
): FindingTriageView {
  const now = options.now ?? Date.now();
  if (!Number.isFinite(now) || now <= 0) throw new Error("Finding triage view clock must be a positive timestamp.");

  const items = report.findings
    .flatMap((finding): FindingTriageViewItem[] => {
      const record = lifecycle.records[finding.fingerprint];
      if (!record) return [];
      const comments = [...commentsForFinding(reviewComments, finding.fingerprint)];
      const reviewStatus = reviewDeadlineStatus(record.reviewAt, now);
      return [{
        fingerprint: finding.fingerprint,
        title: finding.primary.title,
        severity: finding.primary.severity,
        state: record.state,
        updatedAt: record.updatedAt,
        ...(record.owner ? { owner: record.owner } : {}),
        ...(record.note ? { note: record.note } : {}),
        ...(record.reviewAt ? { reviewAt: record.reviewAt } : {}),
        ...(reviewStatus ? { reviewStatus } : {}),
        comments,
      }];
    })
    .sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));

  const assigned = items.filter((item) => Boolean(item.owner)).length;
  const commented = items.filter((item) => item.comments.length > 0).length;
  return {
    schemaVersion: 1,
    reportId: report.reportId,
    items,
    summary: {
      current: items.length,
      assigned,
      unassigned: items.length - assigned,
      commented,
    },
    interpretation: "triage-metadata-not-scanner-evidence",
  };
}
