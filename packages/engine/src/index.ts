import { resolve } from "node:path";
import type { SynSecConfig } from "@synsec/config";
import type { ScanResult, ScanTarget, Severity } from "@synsec/core";
import { applyBaseline, buildReport, type SynSecReport } from "@synsec/report";
import { inventoryRepository } from "@synsec/repository";
import { runProcess, type ScannerAdapter, type ScannerAvailability } from "@synsec/scanner-sdk";
import { builtInScanners } from "@synsec/scanners";

export interface ScannerStatus {
  id: string;
  displayName: string;
  selected: boolean;
  availability: ScannerAvailability;
}

export interface ScannerFailure {
  scanner: string;
  message: string;
}

export interface ScanEngineOutcome {
  report: SynSecReport;
  statuses: ScannerStatus[];
  failures: ScannerFailure[];
  shouldFail: boolean;
}

const severityRank: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  unknown: 0,
};

function sanitizeRemoteUrl(value: string): string {
  try {
    const url = new URL(value);
    if (url.username || url.password) {
      url.username = "";
      url.password = "";
    }
    return url.toString().replace(/\/$/, "");
  } catch {
    return value.replace(/:\/\/[^/@]+@/, "://");
  }
}

async function gitValue(root: string, args: string[]): Promise<string | undefined> {
  try {
    const output = await runProcess("git", ["-C", root, ...args], { timeoutMs: 5_000 });
    if (output.exitCode !== 0) return undefined;
    const value = output.stdout.trim();
    return value || undefined;
  } catch {
    return undefined;
  }
}

export async function discoverTarget(rootPath: string): Promise<ScanTarget> {
  const path = resolve(rootPath);
  const [commitSha, branch, repositoryUrl] = await Promise.all([
    gitValue(path, ["rev-parse", "HEAD"]),
    gitValue(path, ["branch", "--show-current"]),
    gitValue(path, ["config", "--get", "remote.origin.url"]),
  ]);

  const target: ScanTarget = { path };
  if (commitSha) target.commitSha = commitSha;
  if (branch) target.branch = branch;
  if (repositoryUrl) target.repositoryUrl = sanitizeRemoteUrl(repositoryUrl);
  return target;
}

export async function scannerStatuses(config: SynSecConfig): Promise<ScannerStatus[]> {
  const selectedIds = new Set(config.scanners);
  const scanners = builtInScanners();
  const knownIds = new Set(scanners.map((scanner) => scanner.id));
  const statuses = await Promise.all(
    scanners.map(async (scanner) => ({
      id: scanner.id,
      displayName: scanner.displayName,
      selected: selectedIds.has(scanner.id),
      availability: await scanner.checkAvailability(),
    })),
  );

  for (const id of selectedIds) {
    if (!knownIds.has(id)) {
      statuses.push({
        id,
        displayName: id,
        selected: true,
        availability: { available: false, reason: "Unknown scanner id in configuration." },
      });
    }
  }
  return statuses;
}

async function runSelectedScanners(
  target: ScanTarget,
  config: SynSecConfig,
  statuses: readonly ScannerStatus[],
): Promise<{ scans: ScanResult[]; failures: ScannerFailure[] }> {
  const statusById = new Map(statuses.map((status) => [status.id, status]));
  const selected = builtInScanners().filter((scanner) => {
    const status = statusById.get(scanner.id);
    return Boolean(status?.selected && status.availability.available);
  });

  const queue: ScannerAdapter[] = [...selected];
  const scans: ScanResult[] = [];
  const failures: ScannerFailure[] = [];
  const workers = Math.max(1, Math.min(config.parallelism, queue.length || 1));

  await Promise.all(
    Array.from({ length: workers }, async () => {
      while (queue.length > 0) {
        const scanner = queue.shift();
        if (!scanner) return;
        try {
          const result = await scanner.scan({ target, timeoutMs: config.timeoutMs });
          scans.push(result);
        } catch (error) {
          failures.push({
            scanner: scanner.id,
            message: error instanceof Error ? error.message : String(error),
          });
        }
      }
    }),
  );

  scans.sort((a, b) => a.scanner.localeCompare(b.scanner));
  failures.sort((a, b) => a.scanner.localeCompare(b.scanner));
  return { scans, failures };
}

export function reportMeetsFailureThreshold(report: SynSecReport, failOn: SynSecConfig["failOn"]): boolean {
  if (failOn === "none") return false;
  const threshold = severityRank[failOn];
  return report.findings.some((group) => severityRank[group.primary.severity] >= threshold);
}

function unavailableSummary(statuses: readonly ScannerStatus[]): string {
  const selected = statuses.filter((status) => status.selected);
  if (selected.length === 0) return "No scanner engines are selected in the SynSec configuration.";
  const detail = selected
    .map((status) => `${status.displayName}: ${status.availability.reason ?? "unavailable"}`)
    .join("; ");
  return `No selected scanner engines are available. ${detail}`;
}

export async function runScanEngine(input: {
  rootPath: string;
  config: SynSecConfig;
  baseline?: SynSecReport;
  toolVersion?: string;
}): Promise<ScanEngineOutcome> {
  const root = resolve(input.rootPath);
  const [target, statuses, inventory] = await Promise.all([
    discoverTarget(root),
    scannerStatuses(input.config),
    inventoryRepository(root),
  ]);

  const availableSelected = statuses.filter(
    (status) => status.selected && status.availability.available,
  );
  if (availableSelected.length === 0) throw new Error(unavailableSummary(statuses));

  const { scans, failures } = await runSelectedScanners(target, input.config, statuses);
  if (scans.length === 0) {
    const details = failures.map((failure) => `${failure.scanner}: ${failure.message}`).join("; ");
    throw new Error(`All available scanner engines failed.${details ? ` ${details}` : ""}`);
  }

  let report = buildReport({
    target,
    scans,
    toolVersion: input.toolVersion ?? "0.2.0",
    repository: inventory.metadata,
  });
  if (input.baseline) report = applyBaseline(report, input.baseline);

  return {
    report,
    statuses,
    failures,
    shouldFail: reportMeetsFailureThreshold(report, input.config.failOn),
  };
}
