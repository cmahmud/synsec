import { dirname, resolve } from "node:path";
import {
  currentLifecycleRecords,
  isFindingState,
  lifecycleSummary,
  readLifecycleStore,
  reconcileLifecycle,
  setFindingOwner,
  setFindingReviewAt,
  setFindingState,
  verifyRemediation,
  writeLifecycleStore,
  writeRemediationVerification,
  type FindingLifecycleStore,
  type LifecycleSummary,
  type RemediationVerification,
} from "@synsec/lifecycle";
import {
  addFindingReviewComment,
  commentsForFinding,
  readFindingReviewCommentStore,
  writeFindingReviewCommentStore,
} from "@synsec/lifecycle/review-comments";
import { readReport, type SynSecReport } from "@synsec/report";

export interface LifecycleFileResult {
  path: string;
  store: FindingLifecycleStore;
  summary: LifecycleSummary;
}

export async function reconcileLifecycleFile(
  report: SynSecReport,
  root: string,
  persist: boolean,
): Promise<LifecycleFileResult> {
  const path = resolve(root, ".synsec/lifecycle.json");
  const previous = await readLifecycleStore(path);
  const store = reconcileLifecycle(report, previous);
  if (persist) await writeLifecycleStore(path, store);
  return { path, store, summary: lifecycleSummary(store) };
}

function triagePaths(reportPath: string, requestedStore?: string): { lifecycle: string; comments: string } {
  const lifecycle = resolve(requestedStore ?? dirname(reportPath), requestedStore ? "." : "lifecycle.json");
  return {
    lifecycle,
    comments: resolve(dirname(lifecycle), "review-comments.json"),
  };
}

function reviewAtValue(value: string | undefined): string | null | undefined {
  if (value === undefined) return undefined;
  const normalized = value.trim();
  if (!normalized) return undefined;
  return normalized.toLowerCase() === "clear" ? null : normalized;
}

/**
 * Triage CLI operations intentionally mutate only bounded human review metadata.
 * `owner`, `comment`, and `review-at` are explicit operator actions, not scanner states or inferred evidence.
 */
export async function runTriage(input: {
  reportPath: string;
  fingerprint?: string;
  state?: string;
  note?: string;
  reviewAt?: string;
  storePath?: string;
  listOnly?: boolean;
}): Promise<string[]> {
  const reportPath = resolve(input.reportPath);
  const report = await readReport(reportPath);
  const paths = triagePaths(reportPath, input.storePath);
  let store = reconcileLifecycle(report, await readLifecycleStore(paths.lifecycle));
  const comments = await readFindingReviewCommentStore(paths.comments);

  if (input.listOnly) {
    const records = currentLifecycleRecords(report, store);
    const lines = records.map((record) => {
      const finding = report.findings.find((item) => item.fingerprint === record.fingerprint);
      const owner = record.owner ? `  owner:${record.owner}` : "";
      const review = record.reviewAt ? `  review:${record.reviewAt}` : "";
      const commentCount = commentsForFinding(comments, record.fingerprint).length;
      const commentSummary = commentCount > 0 ? `  comments:${commentCount}` : "";
      return `${record.fingerprint}  ${record.state.padEnd(14)}  ${finding?.primary.title ?? "finding"}${owner}${review}${commentSummary}`;
    });
    return [
      `Lifecycle store: ${paths.lifecycle}`,
      `Review comments: ${paths.comments}`,
      ...lines,
    ];
  }

  if (!input.fingerprint || !input.state) {
    throw new Error("Usage: synsec triage <report.json> <fingerprint> <state|owner|comment|review-at> [--note <text>] [--review-at <ISO|clear>] [--store <file>] or synsec triage <report.json> --list");
  }
  const exists = report.findings.some((finding) => finding.fingerprint === input.fingerprint);
  if (!exists) throw new Error(`Finding fingerprint is not present in report ${report.reportId}: ${input.fingerprint}`);

  if (input.state === "owner") {
    if (input.note === undefined) {
      throw new Error("Ownership triage requires --note <owner>; use an empty --note value to clear ownership.");
    }
    store = setFindingOwner(store, input.fingerprint, input.note);
    await writeLifecycleStore(paths.lifecycle, store);
    const owner = store.records[input.fingerprint]?.owner;
    return [
      owner ? `Assigned ${input.fingerprint} -> ${owner}` : `Cleared owner for ${input.fingerprint}`,
      `Lifecycle store: ${paths.lifecycle}`,
    ];
  }

  if (input.state === "review-at") {
    if (input.reviewAt === undefined) {
      throw new Error("Review deadline triage requires --review-at <ISO timestamp|clear>.");
    }
    store = setFindingReviewAt(store, input.fingerprint, reviewAtValue(input.reviewAt));
    await writeLifecycleStore(paths.lifecycle, store);
    const reviewAt = store.records[input.fingerprint]?.reviewAt;
    return [
      reviewAt ? `Review deadline ${input.fingerprint} -> ${reviewAt}` : `Cleared review deadline for ${input.fingerprint}`,
      `Lifecycle store: ${paths.lifecycle}`,
    ];
  }

  if (input.state === "comment") {
    if (!input.note?.trim()) throw new Error("Comment triage requires --note <comment>.");
    const updated = addFindingReviewComment(comments, input.fingerprint, input.note);
    await writeFindingReviewCommentStore(paths.comments, updated);
    const added = commentsForFinding(updated, input.fingerprint).at(-1);
    return [
      `Added review comment to ${input.fingerprint}${added ? ` (${added.id.slice(0, 12)})` : ""}`,
      `Review comments: ${paths.comments}`,
    ];
  }

  if (!isFindingState(input.state)) {
    throw new Error("Triage state must be one of new, confirmed, false-positive, accepted-risk, fixed, regressed; or use owner/comment/review-at actions.");
  }

  store = setFindingState(store, input.fingerprint, input.state, {
    note: input.note,
    reportId: report.reportId,
    reviewAt: reviewAtValue(input.reviewAt),
  });
  await writeLifecycleStore(paths.lifecycle, store);
  return [
    `Updated ${input.fingerprint} -> ${input.state}`,
    ...(store.records[input.fingerprint]?.reviewAt ? [`Review by: ${store.records[input.fingerprint]?.reviewAt}`] : []),
    `Lifecycle store: ${paths.lifecycle}`,
  ];
}

export async function runVerification(input: {
  beforeReportPath: string;
  afterReportPath: string;
  fingerprints?: string[];
  outputPath?: string;
}): Promise<{ verification: RemediationVerification; lines: string[]; outputPath?: string }> {
  const beforePath = resolve(input.beforeReportPath);
  const afterPath = resolve(input.afterReportPath);
  const [before, after] = await Promise.all([readReport(beforePath), readReport(afterPath)]);
  const verification = verifyRemediation(before, after, input.fingerprints);
  const lines = [
    `Verification: ${verification.summary.fixed} fixed, ${verification.summary.persisting} persisting, ${verification.summary.inconclusive} inconclusive, ${verification.summary.newFindings} new finding(s)`,
  ];

  for (const item of verification.items) {
    lines.push(`[${item.status.toUpperCase()}] ${item.title ?? item.fingerprint}`);
    for (const reason of item.reasons) lines.push(`  ${reason}`);
  }
  if (verification.newFindings.length > 0) {
    lines.push("New finding fingerprints:");
    for (const fingerprint of verification.newFindings) lines.push(`  ${fingerprint}`);
  }

  let outputPath: string | undefined;
  if (input.outputPath) {
    outputPath = resolve(input.outputPath);
    await writeRemediationVerification(outputPath, verification);
    lines.push(`Verification JSON: ${outputPath}`);
  }
  return outputPath ? { verification, lines, outputPath } : { verification, lines };
}
