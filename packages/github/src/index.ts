import type { CorrelatedFinding, Severity } from "@synsec/core";
import type { SynSecReport } from "@synsec/report";

export type GitHubCheckConclusion = "success" | "failure" | "neutral";
export type GitHubAnnotationLevel = "notice" | "warning" | "failure";

export interface GitHubPullRequestContext {
  repository: string;
  sha: string;
  ref?: string;
  baseRef?: string;
  headRef?: string;
  pullRequestNumber?: number;
}

export interface GitHubCheckAnnotation {
  path: string;
  start_line: number;
  end_line: number;
  annotation_level: GitHubAnnotationLevel;
  title: string;
  message: string;
  raw_details?: string;
}

export interface GitHubCheckOutput {
  title: string;
  summary: string;
  text: string;
  annotations: GitHubCheckAnnotation[];
}

export interface GitHubCheckResult {
  name: string;
  headSha: string;
  conclusion: GitHubCheckConclusion;
  output: GitHubCheckOutput;
}

const severityRank: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  unknown: 0,
};

function parseRepository(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  return /^[^/\s]+\/[^/\s]+$/.test(trimmed) ? trimmed : undefined;
}

function parsePullRequestNumber(ref: string | undefined): number | undefined {
  if (!ref) return undefined;
  const match = /^refs\/pull\/(\d+)\/(?:merge|head)$/.exec(ref);
  if (!match) return undefined;
  const parsed = Number(match[1]);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : undefined;
}

export function detectGitHubContext(env: NodeJS.ProcessEnv): GitHubPullRequestContext | undefined {
  const repository = parseRepository(env.GITHUB_REPOSITORY);
  const sha = env.GITHUB_SHA?.trim();
  if (!repository || !sha) return undefined;

  const ref = env.GITHUB_REF?.trim() || undefined;
  const baseRef = env.GITHUB_BASE_REF?.trim() || undefined;
  const headRef = env.GITHUB_HEAD_REF?.trim() || undefined;
  const pullRequestNumber = parsePullRequestNumber(ref);

  return {
    repository,
    sha,
    ...(ref ? { ref } : {}),
    ...(baseRef ? { baseRef } : {}),
    ...(headRef ? { headRef } : {}),
    ...(pullRequestNumber ? { pullRequestNumber } : {}),
  };
}

function annotationLevel(severity: Severity): GitHubAnnotationLevel {
  if (severity === "critical" || severity === "high") return "failure";
  if (severity === "medium" || severity === "low") return "warning";
  return "notice";
}

function singleLine(value: string, maxLength = 1024): string {
  const normalized = value.replace(/[\r\n]+/g, " ").replace(/\s+/g, " ").trim();
  if (normalized.length <= maxLength) return normalized;
  return `${normalized.slice(0, Math.max(0, maxLength - 1))}…`;
}

function findingAnnotation(finding: CorrelatedFinding): GitHubCheckAnnotation | undefined {
  const primary = finding.primary;
  const location = primary.location;
  if (!location?.path || !location.startLine) return undefined;

  const sources = finding.sources.map((source) => source.name).join(", ");
  const details = [
    primary.description,
    primary.remediation ? `Remediation: ${primary.remediation}` : undefined,
    sources ? `Sources: ${sources}` : undefined,
    `SynSec fingerprint: ${finding.fingerprint}`,
  ]
    .filter((value): value is string => Boolean(value))
    .join("\n\n");

  return {
    path: location.path.replaceAll("\\", "/").replace(/^\.\//, ""),
    start_line: Math.max(1, location.startLine),
    end_line: Math.max(location.startLine, location.endLine ?? location.startLine),
    annotation_level: annotationLevel(primary.severity),
    title: singleLine(`[${primary.severity.toUpperCase()}] ${primary.title}`, 255),
    message: singleLine(primary.description ?? primary.title),
    ...(details ? { raw_details: details.slice(0, 65_535) } : {}),
  };
}

export function buildGitHubAnnotations(
  report: SynSecReport,
  options: { maxAnnotations?: number; onlyNew?: boolean } = {},
): GitHubCheckAnnotation[] {
  const maxAnnotations = Math.max(0, Math.min(50, options.maxAnnotations ?? 50));
  const newFingerprints = options.onlyNew && report.baseline ? new Set(report.baseline.new) : undefined;

  return report.findings
    .filter((finding) => !newFingerprints || newFingerprints.has(finding.fingerprint))
    .sort((a, b) => {
      const severityDelta = severityRank[b.primary.severity] - severityRank[a.primary.severity];
      if (severityDelta !== 0) return severityDelta;
      return b.primary.confidence - a.primary.confidence;
    })
    .map(findingAnnotation)
    .filter((annotation): annotation is GitHubCheckAnnotation => Boolean(annotation))
    .slice(0, maxAnnotations);
}

export function reportFailsThreshold(report: SynSecReport, threshold: Severity): boolean {
  const required = severityRank[threshold];
  if (required <= 0) return false;
  return report.findings.some((finding) => severityRank[finding.primary.severity] >= required);
}

function markdownSummary(report: SynSecReport, threshold: Severity): string {
  const delta = report.baseline;
  const deltaLine = delta
    ? `New: **${delta.new.length}** · Fixed: **${delta.fixed.length}** · Persisting: **${delta.persisting.length}**`
    : "No baseline comparison was provided.";

  return [
    `Security score: **${report.securityScore}/100** · Findings: **${report.findingCount}**`,
    `Critical: **${report.summary.critical}** · High: **${report.summary.high}** · Medium: **${report.summary.medium}** · Low: **${report.summary.low}**`,
    deltaLine,
    `CI threshold: **${threshold}**`,
  ].join("\n\n");
}

export function buildGitHubCheck(
  report: SynSecReport,
  context: GitHubPullRequestContext,
  options: { threshold?: Severity; onlyNewAnnotations?: boolean; maxAnnotations?: number } = {},
): GitHubCheckResult {
  const threshold = options.threshold ?? "high";
  const failed = reportFailsThreshold(report, threshold);
  const annotations = buildGitHubAnnotations(report, {
    maxAnnotations: options.maxAnnotations,
    onlyNew: options.onlyNewAnnotations ?? Boolean(report.baseline),
  });

  const scope = report.scope?.mode === "changed-files" ? "changed files" : "repository";
  const conclusion: GitHubCheckConclusion = failed ? "failure" : report.findingCount > 0 ? "neutral" : "success";

  return {
    name: "SynSec repository security",
    headSha: context.sha,
    conclusion,
    output: {
      title: failed ? `SynSec found findings at or above ${threshold}` : `SynSec ${scope} scan complete`,
      summary: markdownSummary(report, threshold),
      text: `Report ${report.reportId} scanned ${scope} with ${report.scanners.length} scanner run(s).`,
      annotations,
    },
  };
}
