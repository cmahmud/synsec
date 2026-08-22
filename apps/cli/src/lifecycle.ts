import { dirname, resolve } from "node:path";
import {
  currentLifecycleRecords,
  isFindingState,
  lifecycleSummary,
  readLifecycleStore,
  reconcileLifecycle,
  setFindingState,
  writeLifecycleStore,
  type FindingLifecycleStore,
  type LifecycleSummary,
} from "@synsec/lifecycle";
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

export async function runTriage(input: {
  reportPath: string;
  fingerprint?: string;
  state?: string;
  note?: string;
  storePath?: string;
  listOnly?: boolean;
}): Promise<string[]> {
  const reportPath = resolve(input.reportPath);
  const report = await readReport(reportPath);
  const storePath = resolve(input.storePath ?? dirname(reportPath), input.storePath ? "." : "lifecycle.json");
  let store = reconcileLifecycle(report, await readLifecycleStore(storePath));

  if (input.listOnly) {
    const records = currentLifecycleRecords(report, store);
    const lines = records.map((record) => {
      const finding = report.findings.find((item) => item.fingerprint === record.fingerprint);
      return `${record.fingerprint}  ${record.state.padEnd(14)}  ${finding?.primary.title ?? "finding"}`;
    });
    return [`Lifecycle store: ${storePath}`, ...lines];
  }

  if (!input.fingerprint || !input.state) {
    throw new Error("Usage: synsec triage <report.json> <fingerprint> <state> [--note <text>] [--store <file>] or synsec triage <report.json> --list");
  }
  if (!isFindingState(input.state)) {
    throw new Error("Triage state must be one of new, confirmed, false-positive, accepted-risk, fixed, regressed.");
  }
  const exists = report.findings.some((finding) => finding.fingerprint === input.fingerprint);
  if (!exists) throw new Error(`Finding fingerprint is not present in report ${report.reportId}: ${input.fingerprint}`);

  store = setFindingState(store, input.fingerprint, input.state, {
    note: input.note,
    reportId: report.reportId,
  });
  await writeLifecycleStore(storePath, store);
  return [
    `Updated ${input.fingerprint} -> ${input.state}`,
    `Lifecycle store: ${storePath}`,
  ];
}
