import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { CorrelatedFinding, Finding } from "@synsec/core";
import type { SynSecReport } from "./index.js";

function escapeCell(value: string): string {
  return value.replaceAll("|", "\\|").replaceAll("\n", " ");
}

function location(finding: Finding): string {
  if (!finding.location?.path) return "repository";
  const line = finding.location.startLine ? `:${finding.location.startLine}` : "";
  return `${finding.location.path}${line}`;
}

function identifiers(finding: Finding): string[] {
  const ids = finding.identifiers;
  if (!ids) return [];
  return [...new Set([
    ...(ids.cve ?? []),
    ...(ids.cwe ?? []),
    ...(ids.ghsa ?? []),
    ...(ids.osv ?? []),
  ])];
}

function findingBaselineState(report: SynSecReport, finding: CorrelatedFinding): string | undefined {
  if (!report.baseline) return undefined;
  if (report.baseline.new.includes(finding.fingerprint)) return "new";
  if (report.baseline.persisting.includes(finding.fingerprint)) return "persisting";
  return undefined;
}

function findingSection(report: SynSecReport, group: CorrelatedFinding, index: number): string {
  const finding = group.primary;
  const ids = identifiers(finding);
  const sources = [...new Set(group.sources.map((source) => source.name))].join(", ");
  const baseline = findingBaselineState(report, group);
  const lines = [
    `### ${index + 1}. [${finding.severity.toUpperCase()}] ${finding.title}`,
    "",
    `- **Category:** ${finding.category}`,
    `- **Confidence:** ${Math.round(finding.confidence * 100)}%`,
    `- **Location:** \`${location(finding)}\``,
    `- **Sources:** ${sources || "unknown"}`,
    `- **Fingerprint:** \`${group.fingerprint}\``,
  ];
  if (ids.length > 0) lines.push(`- **Identifiers:** ${ids.join(", ")}`);
  if (baseline) lines.push(`- **Baseline:** ${baseline}`);
  lines.push("");
  if (finding.description) lines.push(finding.description, "");
  if (finding.remediation) lines.push("**Remediation**", "", finding.remediation, "");
  if (group.duplicates.length > 0) {
    lines.push(`Corroborated by ${group.duplicates.length} additional normalized result(s).`, "");
  }
  return lines.join("\n");
}

export function renderMarkdown(report: SynSecReport): string {
  const target = report.target.repositoryUrl ?? report.target.path;
  const scope = report.scope?.mode === "changed-files"
    ? `changed files since ${report.scope.baseRef ?? "configured base"} (${report.scope.changedFiles?.length ?? 0} files)`
    : "repository";
  const sbomPackages = (report.artifacts ?? [])
    .filter((artifact) => artifact.type === "sbom")
    .reduce((total, artifact) => total + artifact.packageCount, 0);

  const lines = [
    "# SynSec Security Report",
    "",
    `**Target:** ${target}`,
    `**Generated:** ${report.generatedAt}`,
    `**Report ID:** \`${report.reportId}\``,
    `**Scan scope:** ${scope}`,
    `**Security score:** ${report.securityScore}/100`,
    "",
    "## Summary",
    "",
    "| Severity | Findings |",
    "| --- | ---: |",
    `| Critical | ${report.summary.critical} |`,
    `| High | ${report.summary.high} |`,
    `| Medium | ${report.summary.medium} |`,
    `| Low | ${report.summary.low} |`,
    `| Info | ${report.summary.info} |`,
    `| Unknown | ${report.summary.unknown} |`,
    "",
    `SynSec correlated **${report.rawFindingCount} raw result(s)** into **${report.findingCount} logical finding(s)**.`,
    "",
    "## Scanner coverage",
    "",
    "| Scanner | Findings | Artifacts | Diagnostics |",
    "| --- | ---: | ---: | --- |",
    ...report.scanners.map((scanner) =>
      `| ${escapeCell(scanner.scanner)} | ${scanner.findingCount} | ${scanner.artifactCount} | ${escapeCell(scanner.diagnostics.join("; ") || "—")} |`,
    ),
    "",
  ];

  if (report.repository) {
    const languages = Object.entries(report.repository.languages ?? {})
      .sort((a, b) => b[1] - a[1])
      .map(([name, count]) => `${name} (${count})`)
      .join(", ");
    lines.push(
      "## Repository context",
      "",
      `- **Files inventoried:** ${report.repository.fileCount ?? "unknown"}`,
      `- **Languages:** ${languages || "unknown"}`,
      `- **Frameworks:** ${(report.repository.frameworks ?? []).join(", ") || "none detected"}`,
      "",
    );
  }

  if (sbomPackages > 0) {
    lines.push(
      "## SBOM",
      "",
      `- **SBOM packages inventoried:** ${sbomPackages}`,
      "",
    );
  }

  if (report.baseline) {
    lines.push(
      "## Baseline delta",
      "",
      `- **New:** ${report.baseline.new.length}`,
      `- **Fixed:** ${report.baseline.fixed.length}`,
      `- **Persisting:** ${report.baseline.persisting.length}`,
      "",
    );
  }

  lines.push("## Findings", "");
  if (report.findings.length === 0) {
    lines.push("No findings were reported by the scanner engines that successfully ran.", "");
  } else {
    report.findings.forEach((finding, index) => lines.push(findingSection(report, finding, index)));
  }

  lines.push(
    "## Interpretation note",
    "",
    "This report preserves deterministic scanner evidence and SynSec correlation. A finding should not be treated as proven exploitable solely because it appears here; confirm reachability, deployment context, and relevant mitigations before remediation decisions.",
    "",
  );
  return `${lines.join("\n").trimEnd()}\n`;
}

export async function writeMarkdown(path: string, report: SynSecReport): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, renderMarkdown(report), "utf8");
}
