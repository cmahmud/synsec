import { createHash } from "node:crypto";
import { chmod, mkdir, open, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type {
  CorrelatedFinding,
  Finding,
  ScanArtifact,
  ScannerExecutionScope,
  ScanResult,
  ScanTarget,
  Severity,
} from "@synsec/core";
import { correlateFindings, findingFingerprint } from "@synsec/core";

export const SYNSEC_REPORT_SCHEMA_VERSION = "1.0" as const;
const MAX_REPORT_BYTES = 64 * 1024 * 1024;

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  unknown: number;
}

export interface ScannerRunSummary {
  scanner: string;
  startedAt: string;
  completedAt: string;
  findingCount: number;
  artifactCount: number;
  diagnostics: string[];
  executionScope?: ScannerExecutionScope;
}

export interface BaselineDelta {
  new: string[];
  fixed: string[];
  persisting: string[];
}

export interface RepositoryMetadata {
  languages?: Record<string, number>;
  frameworks?: string[];
  fileCount?: number;
}

export interface ScanScope {
  mode: "repository" | "changed-files";
  baseRef?: string;
  changedFiles?: string[];
}

export interface SynSecReport {
  schemaVersion: typeof SYNSEC_REPORT_SCHEMA_VERSION;
  reportId: string;
  generatedAt: string;
  toolVersion: string;
  target: ScanTarget;
  scanners: ScannerRunSummary[];
  rawFindingCount: number;
  findingCount: number;
  summary: SeverityCounts;
  securityScore: number;
  findings: CorrelatedFinding[];
  artifacts?: ScanArtifact[];
  scope?: ScanScope;
  baseline?: BaselineDelta;
  repository?: RepositoryMetadata;
}

function emptyCounts(): SeverityCounts {
  return {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    unknown: 0,
  };
}

export function countSeverities(findings: readonly CorrelatedFinding[]): SeverityCounts {
  const counts = emptyCounts();
  for (const finding of findings) counts[finding.primary.severity] += 1;
  return counts;
}

export function calculateSecurityScore(counts: SeverityCounts): number {
  const penalty =
    counts.critical * 25 +
    counts.high * 12 +
    counts.medium * 5 +
    counts.low * 1.5 +
    counts.unknown * 1;
  return Math.max(0, Math.round(100 - Math.min(100, penalty)));
}

function makeReportId(target: ScanTarget, generatedAt: string): string {
  return createHash("sha256")
    .update(`${target.repositoryUrl ?? target.path}|${target.commitSha ?? ""}|${generatedAt}`)
    .digest("hex")
    .slice(0, 20);
}

export function buildReport(input: {
  target: ScanTarget;
  scans: readonly ScanResult[];
  toolVersion?: string;
  repository?: RepositoryMetadata;
  scope?: ScanScope;
}): SynSecReport {
  const rawFindings = input.scans.flatMap((scan) => scan.findings);
  const artifacts = input.scans.flatMap((scan) => scan.artifacts ?? []);
  const findings = correlateFindings(rawFindings);
  const summary = countSeverities(findings);
  const generatedAt = new Date().toISOString();

  const report: SynSecReport = {
    schemaVersion: SYNSEC_REPORT_SCHEMA_VERSION,
    reportId: makeReportId(input.target, generatedAt),
    generatedAt,
    toolVersion: input.toolVersion ?? "0.2.0",
    target: input.target,
    scanners: input.scans.map((scan) => ({
      scanner: scan.scanner,
      startedAt: scan.startedAt,
      completedAt: scan.completedAt,
      findingCount: scan.findings.length,
      artifactCount: scan.artifacts?.length ?? 0,
      diagnostics: scan.diagnostics,
      ...(scan.executionScope ? { executionScope: scan.executionScope } : {}),
    })),
    rawFindingCount: rawFindings.length,
    findingCount: findings.length,
    summary,
    securityScore: calculateSecurityScore(summary),
    findings,
  };

  if (artifacts.length > 0) report.artifacts = artifacts;
  if (input.scope) report.scope = input.scope;
  if (input.repository) report.repository = input.repository;
  return report;
}

function reportFingerprints(report: SynSecReport): Set<string> {
  return new Set(report.findings.map((finding) => finding.fingerprint));
}

export function applyBaseline(report: SynSecReport, baseline: SynSecReport): SynSecReport {
  const current = reportFingerprints(report);
  const previous = reportFingerprints(baseline);

  const delta: BaselineDelta = {
    new: [...current].filter((fingerprint) => !previous.has(fingerprint)).sort(),
    fixed: [...previous].filter((fingerprint) => !current.has(fingerprint)).sort(),
    persisting: [...current].filter((fingerprint) => previous.has(fingerprint)).sort(),
  };

  return { ...report, baseline: delta };
}

export function isSynSecReport(value: unknown): value is SynSecReport {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    record.schemaVersion === SYNSEC_REPORT_SCHEMA_VERSION &&
    typeof record.reportId === "string" &&
    Array.isArray(record.findings)
  );
}

export async function readReport(path: string): Promise<SynSecReport> {
  const handle = await open(path, "r");
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile()) throw new Error(`SynSec report path is not a regular file: ${path}`);
    if (metadata.size > MAX_REPORT_BYTES) throw new Error(`SynSec report exceeds ${MAX_REPORT_BYTES} bytes: ${path}`);
    const parsed = JSON.parse(await handle.readFile("utf8")) as unknown;
    if (!isSynSecReport(parsed)) throw new Error(`Not a supported SynSec report: ${path}`);
    return parsed;
  } finally {
    await handle.close();
  }
}

async function writePrivateFile(path: string, content: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, content, { encoding: "utf8", mode: 0o600 });
  await chmod(path, 0o600).catch(() => undefined);
}

export async function writeReport(path: string, report: SynSecReport): Promise<void> {
  await writePrivateFile(path, `${JSON.stringify(report, null, 2)}\n`);
}

function sarifLevel(severity: Severity): "error" | "warning" | "note" | "none" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  if (severity === "low" || severity === "info") return "note";
  return "none";
}

function ids(finding: Finding): string[] {
  const identifiers = finding.identifiers;
  if (!identifiers) return [];
  return [
    ...(identifiers.cve ?? []),
    ...(identifiers.cwe ?? []),
    ...(identifiers.ghsa ?? []),
    ...(identifiers.osv ?? []),
  ];
}

export function toSarif(report: SynSecReport): Record<string, unknown> {
  const rules = report.findings.map((group) => {
    const finding = group.primary;
    const ruleId = finding.scanner.ruleId ?? group.fingerprint;
    return {
      id: ruleId,
      name: ruleId,
      shortDescription: { text: finding.title },
      fullDescription: { text: finding.description ?? finding.title },
      properties: {
        category: finding.category,
        severity: finding.severity,
        confidence: finding.confidence,
        identifiers: ids(finding),
        scanners: group.sources.map((source) => source.name),
      },
    };
  });

  const results = report.findings.map((group, index) => {
    const finding = group.primary;
    const location = finding.location;
    const result: Record<string, unknown> = {
      ruleId: finding.scanner.ruleId ?? group.fingerprint,
      ruleIndex: index,
      level: sarifLevel(finding.severity),
      message: { text: finding.title },
      partialFingerprints: { "synsec/v1": group.fingerprint },
      properties: {
        category: finding.category,
        confidence: finding.confidence,
        remediation: finding.remediation ?? null,
      },
    };

    if (location) {
      result.locations = [
        {
          physicalLocation: {
            artifactLocation: { uri: location.path },
            region: {
              startLine: location.startLine ?? 1,
              endLine: location.endLine ?? location.startLine ?? 1,
              startColumn: location.startColumn ?? 1,
              endColumn: location.endColumn ?? location.startColumn ?? 1,
            },
          },
        },
      ];
    }
    return result;
  });

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "SynSec",
            semanticVersion: report.toolVersion,
            informationUri: "https://github.com/cmahmud/synsec",
            rules,
          },
        },
        results,
      },
    ],
  };
}

export async function writeSarif(path: string, report: SynSecReport): Promise<void> {
  await writePrivateFile(path, `${JSON.stringify(toSarif(report), null, 2)}\n`);
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function findingLocation(finding: Finding): string {
  if (!finding.location) return "Repository";
  return `${finding.location.path}${finding.location.startLine ? `:${finding.location.startLine}` : ""}`;
}

export function renderHtml(report: SynSecReport): string {
  const cards = report.findings
    .map((group) => {
      const finding = group.primary;
      const sourceNames = group.sources.map((source) => source.name).join(", ");
      const remediation = finding.remediation
        ? `<p><strong>Remediation:</strong> ${escapeHtml(finding.remediation)}</p>`
        : "";
      const description = finding.description
        ? `<p>${escapeHtml(finding.description)}</p>`
        : "";
      return `<article class="finding severity-${escapeHtml(finding.severity)}" data-severity="${escapeHtml(finding.severity)}">
  <div class="finding-head"><span class="pill">${escapeHtml(finding.severity.toUpperCase())}</span><h3>${escapeHtml(finding.title)}</h3></div>
  <div class="meta">${escapeHtml(findingLocation(finding))} · ${escapeHtml(sourceNames)} · confidence ${Math.round(finding.confidence * 100)}%</div>
  ${description}
  ${remediation}
</article>`;
    })
    .join("\n");

  const baseline = report.baseline
    ? `<div class="baseline"><strong>Since baseline:</strong> ${report.baseline.new.length} new · ${report.baseline.fixed.length} fixed · ${report.baseline.persisting.length} persisting</div>`
    : "";
  const sbomPackageCount = (report.artifacts ?? [])
    .filter((artifact) => artifact.type === "sbom")
    .reduce((total, artifact) => total + artifact.packageCount, 0);
  const artifactSummary = sbomPackageCount > 0
    ? `<div class="baseline"><strong>SBOM:</strong> ${sbomPackageCount} package(s) inventoried</div>`
    : "";
  const scopeSummary = report.scope?.mode === "changed-files"
    ? `<div class="baseline"><strong>Scope:</strong> ${report.scope.changedFiles?.length ?? 0} changed file(s)${report.scope.baseRef ? ` since ${escapeHtml(report.scope.baseRef)}` : ""}</div>`
    : "";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>SynSec report</title>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color-scheme:dark;background:#0b0d10;color:#e8edf2}*{box-sizing:border-box}body{margin:0;background:#0b0d10}main{max-width:1120px;margin:0 auto;padding:40px 24px 80px}.top{display:flex;justify-content:space-between;gap:24px;align-items:flex-start}.brand{font-size:14px;letter-spacing:.16em;text-transform:uppercase;color:#8d99a6}.score{font-size:64px;font-weight:800;line-height:1}.muted,.meta{color:#8d99a6}.stats{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px;margin:28px 0}.stat,.finding,.baseline{border:1px solid #242a31;background:#12161b;border-radius:14px;padding:16px}.stat strong{display:block;font-size:26px}.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin:24px 0}.toolbar button{border:1px solid #303740;background:#151a20;color:#dfe7ee;border-radius:999px;padding:8px 12px;cursor:pointer}.toolbar button:hover{background:#1d242c}.finding{margin:12px 0}.finding-head{display:flex;align-items:center;gap:10px}.finding-head h3{margin:0}.pill{font-size:11px;font-weight:800;border:1px solid #3a424c;border-radius:999px;padding:4px 7px}.severity-critical{border-left:4px solid #ff5068}.severity-high{border-left:4px solid #ff8a50}.severity-medium{border-left:4px solid #f2c14e}.severity-low{border-left:4px solid #75b8ff}.severity-info,.severity-unknown{border-left:4px solid #7f8c99}.meta{font-size:13px;margin-top:8px}.baseline{margin-top:16px}@media(max-width:760px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.top{display:block}.score{margin-top:16px}}
</style>
</head>
<body><main>
<div class="top"><div><div class="brand">SynSec repository security</div><h1>${escapeHtml(report.target.repositoryUrl ?? report.target.path)}</h1><div class="muted">Generated ${escapeHtml(report.generatedAt)} · ${report.findingCount} correlated finding(s) from ${report.rawFindingCount} raw result(s)</div>${baseline}${artifactSummary}${scopeSummary}</div><div><div class="muted">Security score</div><div class="score">${report.securityScore}</div></div></div>
<div class="stats">
<div class="stat"><span>Critical</span><strong>${report.summary.critical}</strong></div><div class="stat"><span>High</span><strong>${report.summary.high}</strong></div><div class="stat"><span>Medium</span><strong>${report.summary.medium}</strong></div><div class="stat"><span>Low</span><strong>${report.summary.low}</strong></div><div class="stat"><span>Info</span><strong>${report.summary.info}</strong></div><div class="stat"><span>Unknown</span><strong>${report.summary.unknown}</strong></div>
</div>
<div class="toolbar"><button onclick="filterFindings('all')">All</button><button onclick="filterFindings('critical')">Critical</button><button onclick="filterFindings('high')">High</button><button onclick="filterFindings('medium')">Medium</button><button onclick="filterFindings('low')">Low</button></div>
<section id="findings">${cards || '<div class="finding">No findings. Keep the report as evidence of the scan.</div>'}</section>
</main><script>function filterFindings(s){for(const el of document.querySelectorAll('.finding[data-severity]'))el.style.display=(s==='all'||el.dataset.severity===s)?'block':'none'}</script></body></html>`;
}

export async function writeHtml(path: string, report: SynSecReport): Promise<void> {
  await writePrivateFile(path, renderHtml(report));
}

export function findingIsNew(report: SynSecReport, finding: CorrelatedFinding): boolean {
  return report.baseline ? report.baseline.new.includes(finding.fingerprint) : true;
}

export function rawFingerprint(finding: Finding): string {
  return findingFingerprint(finding);
}
