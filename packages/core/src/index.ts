import { createHash } from "node:crypto";

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "unknown";

export type FindingCategory =
  | "sast"
  | "dependency"
  | "secret"
  | "misconfiguration"
  | "iac"
  | "container"
  | "supply-chain"
  | "repository-posture"
  | "license"
  | "other";

export interface ScannerSource {
  name: string;
  version?: string;
  ruleId?: string;
}

export interface CodeLocation {
  path: string;
  startLine?: number;
  endLine?: number;
  startColumn?: number;
  endColumn?: number;
}

export interface FindingIdentifiers {
  cwe?: string[];
  cve?: string[];
  osv?: string[];
  ghsa?: string[];
}

export interface Finding {
  id: string;
  title: string;
  description?: string;
  category: FindingCategory;
  severity: Severity;
  confidence: number;
  scanner: ScannerSource;
  location?: CodeLocation;
  identifiers?: FindingIdentifiers;
  evidence?: string;
  remediation?: string;
  fingerprint?: string;
  metadata?: Record<string, unknown>;
}

export interface ScanTarget {
  path: string;
  repositoryUrl?: string;
  commitSha?: string;
  branch?: string;
}

export interface ScanResult {
  scanner: string;
  startedAt: string;
  completedAt: string;
  target: ScanTarget;
  findings: Finding[];
  diagnostics: string[];
}

export interface CorrelatedFinding {
  fingerprint: string;
  primary: Finding;
  duplicates: Finding[];
  sources: ScannerSource[];
}

const severityWeight: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  unknown: 0,
};

function normalizedIdentifierSet(finding: Finding): string {
  const ids = finding.identifiers;
  if (!ids) return "";

  return [
    ...(ids.cwe ?? []),
    ...(ids.cve ?? []),
    ...(ids.osv ?? []),
    ...(ids.ghsa ?? []),
  ]
    .map((value) => value.trim().toLowerCase())
    .sort()
    .join(",");
}

export function findingFingerprint(finding: Finding): string {
  if (finding.fingerprint) return finding.fingerprint;

  const location = finding.location;
  const canonical = [
    finding.category,
    finding.scanner.ruleId ?? "",
    location?.path.toLowerCase() ?? "",
    location?.startLine?.toString() ?? "",
    normalizedIdentifierSet(finding),
    finding.title.trim().toLowerCase(),
  ].join("|");

  return createHash("sha256").update(canonical).digest("hex");
}

function shouldReplacePrimary(current: Finding, candidate: Finding): boolean {
  const severityDelta = severityWeight[candidate.severity] - severityWeight[current.severity];
  if (severityDelta !== 0) return severityDelta > 0;
  return candidate.confidence > current.confidence;
}

export function correlateFindings(findings: Finding[]): CorrelatedFinding[] {
  const groups = new Map<string, CorrelatedFinding>();

  for (const finding of findings) {
    const fingerprint = findingFingerprint(finding);
    const existing = groups.get(fingerprint);

    if (!existing) {
      groups.set(fingerprint, {
        fingerprint,
        primary: finding,
        duplicates: [],
        sources: [finding.scanner],
      });
      continue;
    }

    if (shouldReplacePrimary(existing.primary, finding)) {
      existing.duplicates.push(existing.primary);
      existing.primary = finding;
    } else {
      existing.duplicates.push(finding);
    }

    const sourceKey = `${finding.scanner.name}:${finding.scanner.ruleId ?? ""}`;
    const hasSource = existing.sources.some(
      (source) => `${source.name}:${source.ruleId ?? ""}` === sourceKey,
    );

    if (!hasSource) existing.sources.push(finding.scanner);
  }

  return [...groups.values()].sort((a, b) => {
    const severityDelta = severityWeight[b.primary.severity] - severityWeight[a.primary.severity];
    if (severityDelta !== 0) return severityDelta;
    return b.primary.confidence - a.primary.confidence;
  });
}
