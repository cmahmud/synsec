import type { Severity } from "@synsec/core";
import type { SeverityCounts, SynSecReport } from "./index.js";

export interface ReportHistoryPoint {
  reportId: string;
  generatedAt: string;
  commitSha?: string;
  branch?: string;
  securityScore: number;
  findingCount: number;
  summary: SeverityCounts;
  newCount: number;
  fixedCount: number;
  persistingCount: number;
}

export interface FindingHistory {
  fingerprint: string;
  title: string;
  highestSeverity: Severity;
  firstSeenAt: string;
  lastSeenAt: string;
  occurrenceCount: number;
  presentInLatest: boolean;
}

export interface ReportHistory {
  schemaVersion: 1;
  points: ReportHistoryPoint[];
  findings: FindingHistory[];
  scoreDelta: number;
  findingCountDelta: number;
}

const severityRank: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  unknown: 0,
};

function timestamp(report: SynSecReport): number {
  const value = Date.parse(report.generatedAt);
  if (!Number.isFinite(value)) throw new Error(`Report ${report.reportId} has an invalid generatedAt timestamp.`);
  return value;
}

function fingerprints(report: SynSecReport): Set<string> {
  return new Set(report.findings.map((finding) => finding.fingerprint));
}

function deltaCounts(previous: SynSecReport | undefined, current: SynSecReport): Pick<ReportHistoryPoint, "newCount" | "fixedCount" | "persistingCount"> {
  if (!previous) {
    return { newCount: current.findingCount, fixedCount: 0, persistingCount: 0 };
  }

  const before = fingerprints(previous);
  const after = fingerprints(current);
  let newCount = 0;
  let fixedCount = 0;
  let persistingCount = 0;
  for (const fingerprint of after) {
    if (before.has(fingerprint)) persistingCount += 1;
    else newCount += 1;
  }
  for (const fingerprint of before) {
    if (!after.has(fingerprint)) fixedCount += 1;
  }
  return { newCount, fixedCount, persistingCount };
}

export function buildReportHistory(reports: readonly SynSecReport[]): ReportHistory {
  if (reports.length === 0) {
    return { schemaVersion: 1, points: [], findings: [], scoreDelta: 0, findingCountDelta: 0 };
  }

  const ids = new Set<string>();
  for (const report of reports) {
    if (ids.has(report.reportId)) throw new Error(`Duplicate report id in history: ${report.reportId}`);
    ids.add(report.reportId);
  }

  const ordered = [...reports].sort((a, b) => timestamp(a) - timestamp(b) || a.reportId.localeCompare(b.reportId));
  const points: ReportHistoryPoint[] = [];
  const findingMap = new Map<string, FindingHistory>();
  let previous: SynSecReport | undefined;

  for (const report of ordered) {
    const delta = deltaCounts(previous, report);
    points.push({
      reportId: report.reportId,
      generatedAt: report.generatedAt,
      ...(report.target.commitSha ? { commitSha: report.target.commitSha } : {}),
      ...(report.target.branch ? { branch: report.target.branch } : {}),
      securityScore: report.securityScore,
      findingCount: report.findingCount,
      summary: { ...report.summary },
      ...delta,
    });

    for (const correlated of report.findings) {
      const finding = correlated.primary;
      const existing = findingMap.get(correlated.fingerprint);
      if (!existing) {
        findingMap.set(correlated.fingerprint, {
          fingerprint: correlated.fingerprint,
          title: finding.title,
          highestSeverity: finding.severity,
          firstSeenAt: report.generatedAt,
          lastSeenAt: report.generatedAt,
          occurrenceCount: 1,
          presentInLatest: false,
        });
        continue;
      }
      existing.lastSeenAt = report.generatedAt;
      existing.occurrenceCount += 1;
      if (severityRank[finding.severity] > severityRank[existing.highestSeverity]) {
        existing.highestSeverity = finding.severity;
        existing.title = finding.title;
      }
    }
    previous = report;
  }

  const latest = ordered.at(-1);
  const latestFingerprints = latest ? fingerprints(latest) : new Set<string>();
  const findings = [...findingMap.values()]
    .map((finding) => ({ ...finding, presentInLatest: latestFingerprints.has(finding.fingerprint) }))
    .sort((a, b) => severityRank[b.highestSeverity] - severityRank[a.highestSeverity] || a.firstSeenAt.localeCompare(b.firstSeenAt) || a.fingerprint.localeCompare(b.fingerprint));

  const first = points[0];
  const last = points.at(-1);
  return {
    schemaVersion: 1,
    points,
    findings,
    scoreDelta: first && last ? last.securityScore - first.securityScore : 0,
    findingCountDelta: first && last ? last.findingCount - first.findingCount : 0,
  };
}
