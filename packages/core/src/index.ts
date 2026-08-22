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
  /** Native scanner fingerprint when one exists. SynSec computes its own correlation fingerprint. */
  fingerprint?: string;
  metadata?: Record<string, unknown>;
}

export interface SbomPackage {
  name: string;
  version?: string;
  type?: string;
  purl?: string;
  licenses?: string[];
  locations?: string[];
}

export interface SbomArtifact {
  type: "sbom";
  format: "syft-json";
  producer: string;
  generatedAt: string;
  packageCount: number;
  packages: SbomPackage[];
  metadata?: Record<string, unknown>;
}

export type ScanArtifact = SbomArtifact;

export interface ScanTarget {
  path: string;
  repositoryUrl?: string;
  commitSha?: string;
  branch?: string;
}

export type ScannerExecutionMode =
  | "repository"
  | "changed-files-native"
  | "repository-then-filtered";

export interface ScannerExecutionScope {
  mode: ScannerExecutionMode;
  changedFileCount?: number;
  /** Execution mode is provenance for scanner work, not proof that unselected code is unaffected. */
  interpretation: "scanner-execution-scope-not-coverage-proof";
}

export interface ScanResult {
  scanner: string;
  startedAt: string;
  completedAt: string;
  target: ScanTarget;
  findings: Finding[];
  diagnostics: string[];
  artifacts?: ScanArtifact[];
  executionScope?: ScannerExecutionScope;
}

export interface CorrelatedFinding {
  /** Stable SynSec correlation fingerprint, independent of the source scanner fingerprint. */
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

function normalizedValues(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => value.trim().toLowerCase()).filter(Boolean))].sort();
}

function normalizedIdentifierSet(finding: Finding): string[] {
  const ids = finding.identifiers;
  if (!ids) return [];
  return normalizedValues([
    ...(ids.cwe ?? []),
    ...(ids.cve ?? []),
    ...(ids.osv ?? []),
    ...(ids.ghsa ?? []),
  ]);
}

function strongVulnerabilityIdentifiers(finding: Finding): string[] {
  const ids = finding.identifiers;
  if (!ids) return [];

  // Prefer globally interoperable aliases when a scanner gives us several
  // names for the same advisory. This lets an OSV/GHSA-centric scanner and a
  // CVE-centric scanner converge on the same SynSec key instead of diverging
  // merely because one result contains more aliases.
  const cve = normalizedValues(ids.cve ?? []);
  if (cve.length > 0) return cve;
  const ghsa = normalizedValues(ids.ghsa ?? []);
  if (ghsa.length > 0) return ghsa;
  return normalizedValues(ids.osv ?? []);
}

function normalizedPath(finding: Finding): string {
  return (finding.location?.path ?? "")
    .replaceAll("\\", "/")
    .replace(/^\.\//, "")
    .toLowerCase();
}

function normalizedTitle(finding: Finding): string {
  return finding.title.trim().toLowerCase().replace(/\s+/g, " ");
}

function metadataString(finding: Finding, key: string): string {
  const value = finding.metadata?.[key];
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function packageIdentity(finding: Finding): string {
  return metadataString(finding, "purl") || metadataString(finding, "package");
}

function correlationCanonical(finding: Finding): string {
  const path = normalizedPath(finding);
  const line = finding.location?.startLine?.toString() ?? "";
  const strongIds = strongVulnerabilityIdentifiers(finding);

  // Dependency engines frequently use different rule IDs and titles for the
  // same advisory. Advisory IDs plus package identity are substantially more
  // reliable than scanner-specific fingerprints for cross-tool correlation.
  if ((finding.category === "dependency" || finding.category === "container" || finding.category === "supply-chain") && strongIds.length > 0) {
    return ["advisory", finding.category, strongIds.join(","), packageIdentity(finding) || path].join("|");
  }

  // Secret scanners use different rule names for the same value. SynSec never
  // hashes the secret itself; a shared source location is the safest common
  // deterministic signal we can use without retaining credentials.
  if (finding.category === "secret" && path && line) {
    return ["secret-location", path, line].join("|");
  }

  // Two SAST engines that agree on the same CWE at the same source location
  // should normally be presented as corroborating evidence for one issue.
  const cwes = normalizedValues(finding.identifiers?.cwe ?? []);
  if (finding.category === "sast" && path && line && cwes.length > 0) {
    return ["sast-location-cwe", path, line, cwes.join(",")].join("|");
  }

  // Fall back to a conservative scanner-aware key when there is not enough
  // evidence to safely merge alerts from unrelated engines.
  return [
    "exact",
    finding.category,
    finding.scanner.name.toLowerCase(),
    (finding.scanner.ruleId ?? "").toLowerCase(),
    path,
    line,
    normalizedIdentifierSet(finding).join(","),
    normalizedTitle(finding),
  ].join("|");
}

/** Compute SynSec's correlation fingerprint. Native scanner fingerprints remain on Finding.fingerprint. */
export function findingFingerprint(finding: Finding): string {
  return createHash("sha256").update(correlationCanonical(finding)).digest("hex");
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
