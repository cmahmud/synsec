import type { CorrelatedFinding } from "@synsec/core";
import type { BaselineDelta, SynSecReport } from "./index.js";

function normalizePath(value: string): string {
  return value.replaceAll("\\", "/").replace(/^\.\//, "").replace(/^\//, "").toLowerCase();
}

function scannerReran(report: SynSecReport, finding: CorrelatedFinding): boolean {
  const currentScanners = new Set(report.scanners.map((scanner) => scanner.scanner.trim().toLowerCase()).filter(Boolean));
  const detectingScanners = new Set(finding.sources.map((source) => source.name.trim().toLowerCase()).filter(Boolean));
  return [...detectingScanners].some((scanner) => currentScanners.has(scanner));
}

function scopeCoversFinding(report: SynSecReport, finding: CorrelatedFinding): boolean {
  if (!report.scope || report.scope.mode === "repository") return true;
  if (report.scope.mode !== "changed-files") return false;
  const path = finding.primary.location?.path;
  if (!path) return false;
  const changed = new Set((report.scope.changedFiles ?? []).map(normalizePath));
  return changed.has(normalizePath(path));
}

/**
 * Apply a baseline without inventing remediation conclusions outside the current scan's evidence.
 *
 * New/persisting findings are computed from normalized fingerprints as before. An absent baseline
 * finding is considered fixed only when the current report actually covered that finding's path
 * (for changed-file scans) and at least one scanner that previously detected it ran again. Findings
 * that were not reassessed are deliberately omitted from `fixed`; absence is not evidence of a fix.
 */
export function applyEvidenceAwareBaseline(report: SynSecReport, baseline: SynSecReport): SynSecReport {
  const current = new Set(report.findings.map((finding) => finding.fingerprint));
  const previous = new Set(baseline.findings.map((finding) => finding.fingerprint));
  const baselineByFingerprint = new Map(baseline.findings.map((finding) => [finding.fingerprint, finding]));

  const fixed = [...previous]
    .filter((fingerprint) => {
      if (current.has(fingerprint)) return false;
      const finding = baselineByFingerprint.get(fingerprint);
      return Boolean(finding && scopeCoversFinding(report, finding) && scannerReran(report, finding));
    })
    .sort();

  const delta: BaselineDelta = {
    new: [...current].filter((fingerprint) => !previous.has(fingerprint)).sort(),
    fixed,
    persisting: [...current].filter((fingerprint) => previous.has(fingerprint)).sort(),
  };

  return { ...report, baseline: delta };
}
