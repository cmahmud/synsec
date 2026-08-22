import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
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
  const record: FindingLifecycleRecord = {
    fingerprint,
    state,
    updatedAt: options.updatedAt ?? new Date().toISOString(),
  };
  if (options.note?.trim()) record.note = options.note.trim();
  if (options.reportId) record.reportId = options.reportId;
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

export function reconcileLifecycle(
  report: SynSecReport,
  previous: FindingLifecycleStore,
  updatedAt = new Date().toISOString(),
): FindingLifecycleStore {
  const currentFingerprints = new Set(report.findings.map((finding) => finding.fingerprint));
  const all = new Set([...Object.keys(previous.records), ...currentFingerprints]);
  const next: FindingLifecycleStore = { schemaVersion: 1, records: {} };

  for (const fingerprint of all) {
    const prior = previous.records[fingerprint];
    const present = currentFingerprints.has(fingerprint);
    const state = autoTransition(prior, present);
    if (!state) continue;

    const record: FindingLifecycleRecord = {
      fingerprint,
      state,
      updatedAt: prior?.state === state ? prior.updatedAt : updatedAt,
      reportId: report.reportId,
    };
    if (prior?.note) record.note = prior.note;
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
