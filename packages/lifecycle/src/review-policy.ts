import type { LifecycleReviewDeadlineAssessment } from "./review-deadlines.js";

export type LifecycleReviewPolicyViolation = "overdue" | "unscheduled";

export interface LifecycleReviewPolicy {
  failOnOverdue?: boolean;
  failOnUnscheduled?: boolean;
}

export interface LifecycleReviewPolicyResult {
  schemaVersion: 1;
  generatedAt: string;
  ready: boolean;
  violations: LifecycleReviewPolicyViolation[];
  summary: {
    reviewable: number;
    overdue: number;
    dueSoon: number;
    scheduled: number;
    unscheduled: number;
  };
}

/**
 * Evaluate exception-review governance without copying finding identifiers, source paths, owners,
 * notes, report ids, or review timestamps into the policy artifact.
 *
 * This is a governance gate only. It never mutates lifecycle records or converts human exception
 * decisions into scanner-derived finding states.
 */
export function evaluateLifecycleReviewPolicy(
  assessment: LifecycleReviewDeadlineAssessment,
  policy: LifecycleReviewPolicy = {},
): LifecycleReviewPolicyResult {
  if (assessment.schemaVersion !== 1) throw new Error("Unsupported lifecycle review assessment schema version.");

  const counts = assessment.summary;
  for (const [name, value] of Object.entries(counts)) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`Lifecycle review assessment contains an invalid ${name} count.`);
    }
  }
  if (counts.overdue + counts.dueSoon + counts.scheduled + counts.unscheduled !== counts.reviewable) {
    throw new Error("Lifecycle review assessment summary is internally inconsistent.");
  }

  const violations: LifecycleReviewPolicyViolation[] = [];
  if (policy.failOnOverdue === true && counts.overdue > 0) violations.push("overdue");
  if (policy.failOnUnscheduled === true && counts.unscheduled > 0) violations.push("unscheduled");

  return {
    schemaVersion: 1,
    generatedAt: assessment.generatedAt,
    ready: violations.length === 0,
    violations,
    summary: {
      reviewable: counts.reviewable,
      overdue: counts.overdue,
      dueSoon: counts.dueSoon,
      scheduled: counts.scheduled,
      unscheduled: counts.unscheduled,
    },
  };
}
