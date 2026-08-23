import { resolve } from "node:path";
import type { SynSecConfig } from "@synsec/config";
import type { Finding, ScannerExecutionScope, ScanResult, ScanTarget, Severity } from "@synsec/core";
import { buildReport, type SynSecReport } from "@synsec/report";
import { applyEvidenceAwareBaseline } from "@synsec/report/baseline";
import { inventoryRepository } from "@synsec/repository";
import {
  buildRepositoryIndex,
  findingRepositoryContext,
  packageNameFromPurl,
  type RepositoryIndex,
} from "@synsec/repository/analysis";
import { findExternalDependencyUsage } from "@synsec/repository/dependency-usage";
import { buildModuleGraph, type ModuleGraph } from "@synsec/repository/module-graph";
import {
  buildIncrementalScanPlan,
  type IncrementalScanPlan,
} from "@synsec/repository/incremental-plan";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";
import {
  findingRouteProtectionEvidence,
  type RouteProtectionContext,
} from "@synsec/repository/route-protection-context";
import {
  findingRouteSinkFlowEvidence,
  type RouteSinkFlowContext,
} from "@synsec/repository/route-sink-flow";
import {
  runProcess,
  sanitizeOperationalText,
  type ScannerAdapter,
  type ScannerAvailability,
} from "@synsec/scanner-sdk";
import { builtInScanners, scannerSupportsNativeChangedFiles } from "@synsec/scanners";

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
  repositoryIndex: RepositoryIndex;
  statuses: ScannerStatus[];
  failures: ScannerFailure[];
  shouldFail: boolean;
  changedFiles?: string[];
  changedBase?: string;
  incrementalPlan?: IncrementalScanPlan;
}

const severityRank: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  unknown: 0,
};
const EXECUTION_INTERPRETATION = "scanner-execution-scope-not-coverage-proof" as const;
const MAX_SCANNER_DIAGNOSTICS = 1_000;
const ENGINE_OWNED_METADATA_KEYS = new Set<string>([
  "dependencyUsage",
  "repositoryContext",
  "routeFlow",
  "routeProtection",
]);

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

function scannerIdentityLabel(value: string): string {
  return sanitizeOperationalText(value, 256) || "scanner";
}

/**
 * Scanner adapters are an external-process/plugin boundary. Their thrown errors are operational
 * diagnostics, never evidence, so redact and bound them before they can enter reports, logs, or
 * aggregate engine exceptions.
 */
export function scannerFailureMessage(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error);
  return sanitizeOperationalText(raw) || "Scanner failed without an operational diagnostic.";
}

/**
 * Sanitize successful scanner diagnostics at the engine boundary without modifying scanner
 * findings or source evidence. Diagnostic volume is bounded independently from finding volume.
 */
export function sanitizeScanDiagnostics(scan: ScanResult): ScanResult {
  const diagnostics = scan.diagnostics
    .slice(0, MAX_SCANNER_DIAGNOSTICS)
    .map((value) => sanitizeOperationalText(value))
    .filter(Boolean);
  if (scan.diagnostics.length > MAX_SCANNER_DIAGNOSTICS) {
    diagnostics.push(`Additional scanner diagnostics omitted after ${MAX_SCANNER_DIAGNOSTICS} entries.`);
  }
  return { ...scan, diagnostics };
}

function scannerOwnedMetadata(metadata: Finding["metadata"]): Finding["metadata"] {
  if (!metadata) return undefined;
  const entries = Object.entries(metadata).filter(([key]) => !ENGINE_OWNED_METADATA_KEYS.has(key));
  return entries.length > 0 ? Object.fromEntries(entries) : undefined;
}

/**
 * Remove keys reserved for SynSec-derived repository intelligence exactly once when scanner-owned
 * findings cross into the engine. Later enrichment may safely populate those keys without being
 * erased by another trust-boundary pass.
 */
export function stripScannerReservedMetadata(scans: readonly ScanResult[]): ScanResult[] {
  return scans.map((scan) => ({
    ...scan,
    findings: scan.findings.map((finding) => {
      const metadata = scannerOwnedMetadata(finding.metadata);
      if (metadata) return { ...finding, metadata };
      const output = { ...finding };
      delete output.metadata;
      return output;
    }),
  }));
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

function normalizeRepositoryPath(path: string, root: string): string {
  const normalizedRoot = resolve(root).replace(/\\/g, "/").replace(/\/$/, "");
  let normalized = path.replace(/\\/g, "/");
  if (normalized.startsWith(`${normalizedRoot}/`)) normalized = normalized.slice(normalizedRoot.length + 1);
  normalized = normalized.replace(/^\.\//, "").replace(/^\//, "");
  return normalized;
}

function normalizeProvidedChangedFiles(files: readonly string[], root: string): string[] {
  if (files.length > 10_000) throw new Error("Externally supplied changed-file scope exceeds 10000 paths.");
  const normalized: string[] = [];
  for (const value of files) {
    if (typeof value !== "string" || value.includes("\0")) throw new Error("Externally supplied changed-file scope contains an invalid path.");
    const candidate = value.trim().replaceAll("\\", "/").replace(/^\.\//, "");
    if (!candidate || candidate.startsWith("/") || /^[A-Za-z]:\//.test(candidate)) {
      throw new Error("Externally supplied changed-file scope must contain repository-relative paths.");
    }
    const segments = candidate.split("/");
    if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
      throw new Error("Externally supplied changed-file scope contains an unsafe path segment.");
    }
    normalized.push(normalizeRepositoryPath(candidate, root));
  }
  return [...new Map(normalized.map((path) => [path.toLowerCase(), path])).values()].sort();
}

export async function discoverChangedFiles(rootPath: string, requestedBase?: string): Promise<{ base: string; files: string[] }> {
  const root = resolve(rootPath);
  const githubBase = process.env.GITHUB_BASE_REF?.trim();
  const base = requestedBase ?? (githubBase ? `origin/${githubBase}` : "HEAD~1");
  let output = await runProcess(
    "git",
    ["-C", root, "diff", "--name-only", "--diff-filter=ACMRTUXB", `${base}...HEAD`],
    { timeoutMs: 10_000 },
  );

  if (output.exitCode !== 0 && !requestedBase && githubBase) {
    output = await runProcess(
      "git",
      ["-C", root, "diff", "--name-only", "--diff-filter=ACMRTUXB", `${githubBase}...HEAD`],
      { timeoutMs: 10_000 },
    );
  }

  if (output.exitCode !== 0) {
    throw new Error(`Unable to determine changed files from ${base}: ${output.stderr.trim() || "git diff failed"}`);
  }

  const files = [...new Set(
    output.stdout
      .split(/\r?\n/)
      .map((value) => normalizeRepositoryPath(value.trim(), root))
      .filter(Boolean),
  )].sort();
  return { base, files };
}

function findingMatchesChangedFiles(finding: Finding, changed: Set<string>, root: string): boolean {
  if (!finding.location?.path) return true;
  const path = normalizeRepositoryPath(finding.location.path, root).toLowerCase();
  return changed.has(path);
}

function scopeScansToChangedFiles(scans: readonly ScanResult[], root: string, files: readonly string[]): ScanResult[] {
  const changed = new Set(files.map((file) => normalizeRepositoryPath(file, root).toLowerCase()));
  return scans.map((scan) => {
    const before = scan.findings.length;
    const findings = scan.findings.filter((finding) => findingMatchesChangedFiles(finding, changed, root));
    const dropped = before - findings.length;
    return {
      ...scan,
      findings,
      diagnostics: dropped > 0
        ? [...scan.diagnostics, `Changed-file scope omitted ${dropped} finding(s) outside the requested diff.`]
        : scan.diagnostics,
    };
  });
}

function dependencyPackageName(finding: Finding): string | undefined {
  const direct = finding.metadata?.package;
  if (typeof direct === "string" && direct.trim()) return direct.trim();
  const purl = finding.metadata?.purl;
  return typeof purl === "string" ? packageNameFromPurl(purl) : undefined;
}

function enrichDependencyUsage(
  scans: readonly ScanResult[],
  index: RepositoryIndex,
  moduleGraph: ModuleGraph,
): ScanResult[] {
  return scans.map((scan) => ({
    ...scan,
    findings: scan.findings.map((finding) => {
      if (finding.category !== "dependency" && finding.category !== "container" && finding.category !== "supply-chain") {
        return finding;
      }
      const packageName = dependencyPackageName(finding);
      if (!packageName) return finding;
      const usage = findExternalDependencyUsage(index, moduleGraph, packageName);
      return {
        ...finding,
        metadata: {
          ...(finding.metadata ?? {}),
          dependencyUsage: usage,
        },
      };
    }),
  }));
}

/**
 * Attach minimized repository intelligence only when it can be correlated to the finding's exact
 * normalized location. Inputs are expected to have crossed stripScannerReservedMetadata() first.
 * Secret findings remain outside this enrichment boundary. Route-protection context is structural
 * auth evidence only; it never upgrades or suppresses scanner evidence.
 */
export function enrichRepositorySecurityContext(
  scans: readonly ScanResult[],
  index: RepositoryIndex,
  routeFlows: readonly RouteSinkFlowContext[],
  routeProtections: readonly RouteProtectionContext[] = [],
): ScanResult[] {
  return scans.map((scan) => ({
    ...scan,
    findings: scan.findings.map((finding) => {
      // Secret findings intentionally stay on the narrowest metadata boundary.
      if (finding.category === "secret" || !finding.location?.path) return finding;
      const context = findingRepositoryContext(index, finding.location.path, finding.location.startLine);
      const routeFlow = findingRouteSinkFlowEvidence(
        routeFlows,
        finding.location.path,
        finding.location.startLine,
      );
      const routeProtection = findingRouteProtectionEvidence(
        routeProtections,
        routeFlows,
        finding.location.path,
        finding.location.startLine,
      );
      const hasContext =
        context.nearbyRoutes.length > 0 ||
        context.nearbyAuthSignals.length > 0 ||
        context.nearbySinks.length > 0;
      if (!hasContext && routeFlow.length === 0 && routeProtection.length === 0) return finding;
      return {
        ...finding,
        metadata: {
          ...(finding.metadata ?? {}),
          ...(hasContext ? { repositoryContext: context } : {}),
          ...(routeFlow.length > 0 ? { routeFlow } : {}),
          ...(routeProtection.length > 0 ? { routeProtection } : {}),
        },
      };
    }),
  }));
}

export async function scannerStatuses(config: SynSecConfig): Promise<ScannerStatus[]> {
  const selectedIds = new Set(config.scanners);
  const scanners = builtInScanners();
  const knownIds = new Set(scanners.map((scanner) => scanner.id));
  const statuses = await Promise.all(
    scanners.map(async (scanner) => {
      let availability: ScannerAvailability;
      try {
        availability = await scanner.checkAvailability();
      } catch (error) {
        availability = {
          available: false,
          reason: scannerFailureMessage(error),
        };
      }
      return {
        id: scanner.id,
        displayName: scanner.displayName,
        selected: selectedIds.has(scanner.id),
        availability,
      };
    }),
  );

  for (const id of selectedIds) {
    if (!knownIds.has(id)) {
      const label = scannerIdentityLabel(id);
      statuses.push({
        id: label,
        displayName: label,
        selected: true,
        availability: { available: false, reason: "Unknown scanner id in configuration." },
      });
    }
  }
  return statuses;
}

function defaultScannerExecutionScope(scannerId: string, changedFiles?: readonly string[]): ScannerExecutionScope {
  if (!changedFiles) return { mode: "repository", interpretation: EXECUTION_INTERPRETATION };
  return {
    mode: scannerSupportsNativeChangedFiles(scannerId) ? "changed-files-native" : "repository-then-filtered",
    changedFileCount: changedFiles.length,
    interpretation: EXECUTION_INTERPRETATION,
  };
}

async function runSelectedScanners(
  target: ScanTarget,
  config: SynSecConfig,
  statuses: readonly ScannerStatus[],
  changedFiles?: string[],
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
          const result = await scanner.scan({ target, timeoutMs: config.timeoutMs, changedFiles });
          const sanitized = sanitizeScanDiagnostics(result);
          scans.push({
            ...sanitized,
            executionScope: sanitized.executionScope ?? defaultScannerExecutionScope(scanner.id, changedFiles),
          });
        } catch (error) {
          failures.push({
            scanner: scanner.id,
            message: scannerFailureMessage(error),
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
    .map((status) => `${scannerIdentityLabel(status.displayName)}: ${sanitizeOperationalText(status.availability.reason ?? "unavailable", 2_048) || "unavailable"}`)
    .join("; ");
  return `No selected scanner engines are available. ${detail}`;
}

export async function runScanEngine(input: {
  rootPath: string;
  config: SynSecConfig;
  baseline?: SynSecReport;
  toolVersion?: string;
  changedOnly?: boolean;
  changedBase?: string;
  /** Repository-relative paths derived by a trusted caller from exact commit provenance. */
  changedFiles?: readonly string[];
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

  const repositoryIndex = await buildRepositoryIndex(root, inventory.files);
  const moduleGraph = buildModuleGraph(repositoryIndex, inventory.files);
  let routeFlows: RouteSinkFlowContext[] = [];
  let routeProtections: RouteProtectionContext[] = [];
  if (repositoryIndex.routes.length > 0 && repositoryIndex.sinks.length > 0) {
    const routeAnalysis = await buildRepositoryRouteFlowAnalysis(
      root,
      inventory.files,
      repositoryIndex,
      moduleGraph,
    );
    routeFlows = routeAnalysis.routeFlows;
    routeProtections = routeAnalysis.routeProtectionContexts;
  }

  let requestedScope: { base: string; files: string[] } | undefined;
  if (input.changedFiles !== undefined) {
    if (!input.changedOnly) throw new Error("Externally supplied changed files require changedOnly=true.");
    const base = input.changedBase?.trim();
    if (!base) throw new Error("Externally supplied changed files require an explicit changedBase provenance identifier.");
    requestedScope = { base, files: normalizeProvidedChangedFiles(input.changedFiles, root) };
  } else if (input.changedOnly) {
    requestedScope = await discoverChangedFiles(root, input.changedBase);
  }

  let changedScope: { base: string; files: string[] } | undefined;
  let incrementalPlan: IncrementalScanPlan | undefined;
  if (requestedScope) {
    incrementalPlan = buildIncrementalScanPlan(moduleGraph, requestedScope.files);
    if (incrementalPlan.mode === "targeted" && incrementalPlan.selectedFiles.length > 0) {
      changedScope = { base: requestedScope.base, files: incrementalPlan.selectedFiles };
    }
  }

  const result = await runSelectedScanners(target, input.config, statuses, changedScope?.files);
  const scannerBounded = stripScannerReservedMetadata(result.scans);
  const dependencyEnriched = enrichDependencyUsage(scannerBounded, repositoryIndex, moduleGraph);
  const enrichedScans = enrichRepositorySecurityContext(
    dependencyEnriched,
    repositoryIndex,
    routeFlows,
    routeProtections,
  );
  const scans = changedScope ? scopeScansToChangedFiles(enrichedScans, root, changedScope.files) : enrichedScans;
  const failures = result.failures;
  if (scans.length === 0) {
    const details = failures.map((failure) => `${failure.scanner}: ${failure.message}`).join("; ");
    throw new Error(`All available scanner engines failed.${details ? ` ${details}` : ""}`);
  }

  let report = buildReport({
    target,
    scans,
    toolVersion: input.toolVersion ?? "0.2.0",
    repository: inventory.metadata,
    scope: changedScope
      ? { mode: "changed-files", baseRef: changedScope.base, changedFiles: changedScope.files }
      : { mode: "repository" },
  });
  if (input.baseline) report = applyEvidenceAwareBaseline(report, input.baseline);

  const outcome: ScanEngineOutcome = {
    report,
    repositoryIndex,
    statuses,
    failures,
    shouldFail: reportMeetsFailureThreshold(report, input.config.failOn),
  };
  if (changedScope) {
    outcome.changedFiles = changedScope.files;
    outcome.changedBase = changedScope.base;
  }
  if (incrementalPlan) outcome.incrementalPlan = incrementalPlan;
  return outcome;
}
