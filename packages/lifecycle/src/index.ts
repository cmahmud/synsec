import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { CorrelatedFinding } from "@synsec/core";
import type { SynSecReport } from "@synsec/report";

export type FindingState =
  | "new"
  | "confirmed"
  | "false-positive"
  | "accepted-risk"
  | "fixed"
  | "regressed";

export interface FindingLifecycleRecord {
  fingerprint: string;
  state: FindingState;
  updatedAt: string;
  note?: string;
  reportId?: string;
  /** Last source path observed for scope-aware incremental reconciliation. */
  lastSeenPath?: string;
}

export interface FindingLifecycleStore {
  schemaVersion: 1;
  records: Record<string, FindingLifecycleRecord>;
}

export interface LifecycleSummary {
  new: number;
  confirmed: number;
  falsePositive: number;
  acceptedRisk: number;
  fixed: number;
  regressed: number;
}

export type VerificationStatus = "fixed" | "persisting" | "inconclusive" | "missing-baseline";

export interface FindingVerification {
  fingerprint: string;
  title?: string;
  status: VerificationStatus;
  reasons: string[];
}

export interface RemediationVerification {
  schemaVersion: 1;
  generatedAt: string;
  beforeReportId: string;
  afterReportId: string;
  items: FindingVerification[];
  newFindings: string[];
  summary: {
    fixed: number;
    persisting: number;
    inconclusive: number;
    missingBaseline: number;
    newFindings: number;
  };
}

export function emptyLifecycleStore(): FindingLifecycleStore {
  return { schemaVersion: 1, records: {} };
}

export function isFindingState(value: unknown): value is FindingState {
  return value === "new" || value === "confirmed" || value === "false-positive" || value === "accepted-risk" || value === "fixed" || value === "regressed";
}

export function isLifecycleStore(value: unknown): value is FindingLifecycleStore {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return record.schemaVersion === 1 && typeof record.records === "object" && record.records !== null && !Array.isArray(record.records);
}

export async function readLifecycleStore(path: string): Promise<FindingLifecycleStore> {
  try {
    const parsed = JSON.parse(await readFile(path, "utf8")) as unknown;
    if (!isLifecycleStore(parsed)) throw new Error(`Not a supported SynSec lifecycle store: ${path}`);
    return parsed;
  } catch (error) {
    const code = typeof error === "object" && error !== null && "code" in error
      ? String((error as { code?: unknown }).code)
      : "";
    if (code === "ENOENT") return emptyLifecycleStore();
    throw error;
  }
}

export async function writeLifecycleStore(path: string, store: FindingLifecycleStore): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(store, null, 2)}\n`, "utf8");
}

export function setFindingState(
  store: FindingLifecycleStore,
  fingerprint: string,
  state: FindingState,
  options: { note?: string; reportId?: string; updatedAt?: string } = {},
): FindingLifecycleStore {
  if (!fingerprint.trim()) throw new Error("Finding fingerprint cannot be empty.");
  const updated: FindingLifecycleStore = {
    schemaVersion: 1,
    records: { ...store.records },
  };
  const previous = store.records[fingerprint];
  const record: FindingLifecycleRecord = {
    fingerprint,
    state,
    updatedAt: options.updatedAt ?? new Date().toISOString(),
  };
  const note = options.note?.trim() || previous?.note;
  if (note) record.note = note;
  const reportId = options.reportId ?? previous?.reportId;
  if (reportId) record.reportId = reportId;
  if (previous?.lastSeenPath) record.lastSeenPath = previous.lastSeenPath;
  updated.records[fingerprint] = record;
  return updated;
}

function autoTransition(previous: FindingLifecycleRecord | undefined, present: boolean): FindingState | undefined {
  if (present) {
    if (!previous) return "new";
    if (previous.state === "fixed") return "regressed";
    return previous.state;
  }

  if (!previous) return undefined;
  if (previous.state === "new" || previous.state === "confirmed" || previous.state === "regressed") return "fixed";
  return previous.state;
}

function normalizePath(value: string): string {
  return value.replaceAll("\\", "/").replace(/^\.\//, "").replace(/^\//, "").toLowerCase();
}

function reportCanConcludeAbsence(report: SynSecReport, previous: FindingLifecycleRecord): boolean {
  if (report.scope?.mode === "repository") return true;
  if (report.scope?.mode !== "changed-files" || !previous.lastSeenPath) return false;
  const changed = new Set((report.scope.changedFiles ?? []).map(normalizePath));
  return changed.has(normalizePath(previous.lastSeenPath));
}

export function reconcileLifecycle(
  report: SynSecReport,
  previous: FindingLifecycleStore,
  updatedAt = new Date().toISOString(),
): FindingLifecycleStore {
  const currentByFingerprint = new Map(report.findings.map((finding) => [finding.fingerprint, finding]));
  const all = new Set([...Object.keys(previous.records), ...currentByFingerprint.keys()]);
  const next: FindingLifecycleStore = { schemaVersion: 1, records: {} };

  for (const fingerprint of all) {
    const prior = previous.records[fingerprint];
    const current = currentByFingerprint.get(fingerprint);
    const present = Boolean(current);
    const absenceCovered = prior ? reportCanConcludeAbsence(report, prior) : false;
    const state = present
      ? autoTransition(prior, true)
      : absenceCovered
        ? autoTransition(prior, false)
        : prior?.state;
    if (!state) continue;

    const stateChanged = prior?.state !== state;
    const record: FindingLifecycleRecord = {
      fingerprint,
      state,
      updatedAt: stateChanged ? updatedAt : (prior?.updatedAt ?? updatedAt),
    };

    if (present || absenceCovered) record.reportId = report.reportId;
    else if (prior?.reportId) record.reportId = prior.reportId;
    if (prior?.note) record.note = prior.note;
    const lastSeenPath = current?.primary.location?.path ?? prior?.lastSeenPath;
    if (lastSeenPath) record.lastSeenPath = lastSeenPath;
    next.records[fingerprint] = record;
  }

  return next;
}

export function lifecycleSummary(store: FindingLifecycleStore): LifecycleSummary {
  const summary: LifecycleSummary = {
    new: 0,
    confirmed: 0,
    falsePositive: 0,
    acceptedRisk: 0,
    fixed: 0,
    regressed: 0,
  };
  for (const record of Object.values(store.records)) {
    if (record.state === "new") summary.new += 1;
    else if (record.state === "confirmed") summary.confirmed += 1;
    else if (record.state === "false-positive") summary.falsePositive += 1;
    else if (record.state === "accepted-risk") summary.acceptedRisk += 1;
    else if (record.state === "fixed") summary.fixed += 1;
    else if (record.state === "regressed") summary.regressed += 1;
  }
  return summary;
}

export function currentLifecycleRecords(
  report: SynSecReport,
  store: FindingLifecycleStore,
): FindingLifecycleRecord[] {
  const current = new Set(report.findings.map((finding) => finding.fingerprint));
  return Object.values(store.records)
    .filter((record) => current.has(record.fingerprint))
    .sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
}

function afterScopeCoversFinding(after: SynSecReport, finding: CorrelatedFinding): { covered: boolean; reason?: string } {
  if (after.scope?.mode === "repository") return { covered: true };
  if (after.scope?.mode !== "changed-files") {
    return { covered: false, reason: "The after report has no repository-wide or changed-file scan scope metadata." };
  }
  const path = finding.primary.location?.path;
  if (!path) {
    return { covered: false, reason: "The finding has no source path, so a changed-file scan cannot prove it was rechecked." };
  }
  const changed = new Set((after.scope.changedFiles ?? []).map(normalizePath));
  if (!changed.has(normalizePath(path))) {
    return { covered: false, reason: `The after report did not scan the finding path ${path} in its changed-file scope.` };
  }
  return { covered: true };
}

function afterReranDetectingScanner(after: SynSecReport, finding: CorrelatedFinding): { covered: boolean; reason?: string } {
  const afterScanners = new Set(after.scanners.map((scanner) => scanner.scanner.toLowerCase()));
  const detecting = [...new Set(finding.sources.map((source) => source.name.toLowerCase()))];
  if (detecting.some((name) => afterScanners.has(name))) return { covered: true };
  return {
    covered: false,
    reason: `None of the scanner(s) that detected the finding were present in the after report: ${detecting.join(", ") || "unknown"}.`,
  };
}

export function verifyRemediation(
  before: SynSecReport,
  after: SynSecReport,
  requestedFingerprints?: readonly string[],
  generatedAt = new Date().toISOString(),
): RemediationVerification {
  const beforeByFingerprint = new Map(before.findings.map((finding) => [finding.fingerprint, finding]));
  const afterByFingerprint = new Map(after.findings.map((finding) => [finding.fingerprint, finding]));
  const targets = requestedFingerprints && requestedFingerprints.length > 0
    ? [...new Set(requestedFingerprints)]
    : before.findings.map((finding) => finding.fingerprint);

  const items: FindingVerification[] = targets.map((fingerprint) => {
    const baseline = beforeByFingerprint.get(fingerprint);
    if (!baseline) {
      return {
        fingerprint,
        status: "missing-baseline" as const,
        reasons: ["The requested fingerprint is not present in the before report."],
      };
    }
    if (afterByFingerprint.has(fingerprint)) {
      return {
        fingerprint,
        title: baseline.primary.title,
        status: "persisting" as const,
        reasons: ["The same correlated finding fingerprint is still present after remediation."],
      };
    }

    const scannerCoverage = afterReranDetectingScanner(after, baseline);
    const scopeCoverage = afterScopeCoversFinding(after, baseline);
    const reasons = [scannerCoverage.reason, scopeCoverage.reason].filter((value): value is string => Boolean(value));
    if (!scannerCoverage.covered || !scopeCoverage.covered) {
      return {
        fingerprint,
        title: baseline.primary.title,
        status: "inconclusive" as const,
        reasons,
      };
    }

    return {
      fingerprint,
      title: baseline.primary.title,
      status: "fixed" as const,
      reasons: ["The finding disappeared after a detecting scanner re-ran over the affected scope."],
    };
  });

  const beforeFingerprints = new Set(before.findings.map((finding) => finding.fingerprint));
  const newFindings = after.findings
    .map((finding) => finding.fingerprint)
    .filter((fingerprint) => !beforeFingerprints.has(fingerprint))
    .sort();

  return {
    schemaVersion: 1,
    generatedAt,
    beforeReportId: before.reportId,
    afterReportId: after.reportId,
    items,
    newFindings,
    summary: {
      fixed: items.filter((item) => item.status === "fixed").length,
      persisting: items.filter((item) => item.status === "persisting").length,
      inconclusive: items.filter((item) => item.status === "inconclusive").length,
      missingBaseline: items.filter((item) => item.status === "missing-baseline").length,
      newFindings: newFindings.length,
    },
  };
}

export async function writeRemediationVerification(path: string, verification: RemediationVerification): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(verification, null, 2)}\n`, "utf8");
}
