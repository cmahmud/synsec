import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { Severity } from "@synsec/core";
import type { SeverityCounts, SynSecReport } from "./index.js";
import { buildReportHistory, type ReportHistory, type ReportHistoryInput } from "./history.js";

export const HISTORY_STORE_SCHEMA_VERSION = 1 as const;
export const DEFAULT_HISTORY_RETENTION = 100;
export const MAX_HISTORY_RETENTION = 10_000;

export interface StoredFindingSnapshot {
  fingerprint: string;
  primary: {
    title: string;
    severity: Severity;
  };
}

export interface StoredReportSnapshot extends ReportHistoryInput {
  target: {
    commitSha?: string;
    branch?: string;
  };
  summary: SeverityCounts;
  findings: StoredFindingSnapshot[];
}

export interface ReportHistoryStore {
  schemaVersion: typeof HISTORY_STORE_SCHEMA_VERSION;
  reports: StoredReportSnapshot[];
}

export interface AppendHistoryOptions {
  maxReports?: number;
}

function isSeverity(value: unknown): value is Severity {
  return value === "critical" || value === "high" || value === "medium" || value === "low" || value === "info" || value === "unknown";
}

function isSeverityCounts(value: unknown): value is SeverityCounts {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return ["critical", "high", "medium", "low", "info", "unknown"].every(
    (key) => typeof record[key] === "number" && Number.isFinite(record[key]) && (record[key] as number) >= 0,
  );
}

function isStoredReportSnapshot(value: unknown): value is StoredReportSnapshot {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  if (
    typeof record.reportId !== "string" ||
    typeof record.generatedAt !== "string" ||
    !Number.isFinite(Date.parse(record.generatedAt)) ||
    typeof record.securityScore !== "number" ||
    !Number.isFinite(record.securityScore) ||
    typeof record.findingCount !== "number" ||
    !Number.isInteger(record.findingCount) ||
    record.findingCount < 0 ||
    !isSeverityCounts(record.summary) ||
    !Array.isArray(record.findings) ||
    typeof record.target !== "object" ||
    record.target === null
  ) {
    return false;
  }

  const target = record.target as Record<string, unknown>;
  if (target.commitSha !== undefined && typeof target.commitSha !== "string") return false;
  if (target.branch !== undefined && typeof target.branch !== "string") return false;

  return record.findings.every((finding) => {
    if (typeof finding !== "object" || finding === null) return false;
    const item = finding as Record<string, unknown>;
    if (typeof item.fingerprint !== "string" || typeof item.primary !== "object" || item.primary === null) return false;
    const primary = item.primary as Record<string, unknown>;
    return typeof primary.title === "string" && isSeverity(primary.severity);
  });
}

export function snapshotReport(report: SynSecReport): StoredReportSnapshot {
  return {
    reportId: report.reportId,
    generatedAt: report.generatedAt,
    target: {
      ...(report.target.commitSha ? { commitSha: report.target.commitSha } : {}),
      ...(report.target.branch ? { branch: report.target.branch } : {}),
    },
    securityScore: report.securityScore,
    findingCount: report.findingCount,
    summary: { ...report.summary },
    findings: report.findings.map((finding) => ({
      fingerprint: finding.fingerprint,
      primary: {
        title: finding.primary.title,
        severity: finding.primary.severity,
      },
    })),
  };
}

export async function readHistoryStore(path: string): Promise<ReportHistoryStore> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { schemaVersion: HISTORY_STORE_SCHEMA_VERSION, reports: [] };
    }
    throw error;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new Error(`History store is not valid JSON: ${path}`);
  }

  if (typeof parsed !== "object" || parsed === null) throw new Error(`Unsupported SynSec history store: ${path}`);
  const record = parsed as Record<string, unknown>;
  if (record.schemaVersion !== HISTORY_STORE_SCHEMA_VERSION || !Array.isArray(record.reports) || !record.reports.every(isStoredReportSnapshot)) {
    throw new Error(`Unsupported SynSec history store: ${path}`);
  }

  return { schemaVersion: HISTORY_STORE_SCHEMA_VERSION, reports: record.reports };
}

function retentionLimit(value: number | undefined): number {
  const limit = value ?? DEFAULT_HISTORY_RETENTION;
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_HISTORY_RETENTION) {
    throw new Error(`History retention must be an integer between 1 and ${MAX_HISTORY_RETENTION}.`);
  }
  return limit;
}

async function writeHistoryStore(path: string, store: ReportHistoryStore): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(store, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true });
  }
}

export async function appendHistoryReport(
  path: string,
  report: SynSecReport,
  options: AppendHistoryOptions = {},
): Promise<ReportHistoryStore> {
  const limit = retentionLimit(options.maxReports);
  const store = await readHistoryStore(path);
  const snapshot = snapshotReport(report);
  const reports = store.reports.filter((existing) => existing.reportId !== snapshot.reportId);
  reports.push(snapshot);
  reports.sort((a, b) => Date.parse(a.generatedAt) - Date.parse(b.generatedAt) || a.reportId.localeCompare(b.reportId));
  const bounded = reports.slice(Math.max(0, reports.length - limit));
  const next = { schemaVersion: HISTORY_STORE_SCHEMA_VERSION, reports: bounded } as const;
  await writeHistoryStore(path, next);
  return next;
}

export async function buildHistoryFromStore(path: string): Promise<ReportHistory> {
  const store = await readHistoryStore(path);
  return buildReportHistory(store.reports);
}
