import { appendFile } from "node:fs/promises";
import type { SynSecReport } from "@synsec/report";

export function renderStepSummary(report: SynSecReport, baselineSource: string): string {
  const delta = report.baseline;
  const lines = [
    "## SynSec repository security",
    "",
    `**Security score:** ${report.securityScore}/100  `,
    `**Findings:** ${report.findingCount}  `,
    `**Scope:** ${report.scope?.mode === "changed-files" ? "changed files" : "full repository"}  `,
    `**Baseline:** ${baselineSource}`,
    "",
    "| Severity | Count |",
    "| --- | ---: |",
    `| Critical | ${report.summary.critical} |`,
    `| High | ${report.summary.high} |`,
    `| Medium | ${report.summary.medium} |`,
    `| Low | ${report.summary.low} |`,
    `| Info | ${report.summary.info} |`,
    `| Unknown | ${report.summary.unknown} |`,
  ];
  if (delta) {
    lines.push(
      "",
      "### Baseline delta",
      "",
      `New: **${delta.new.length}** · Fixed: **${delta.fixed.length}** · Persisting: **${delta.persisting.length}**`,
    );
  }
  lines.push(
    "",
    "_This summary intentionally contains aggregate metadata only. Review the normalized report/check annotations for finding details._",
    "",
  );
  return `${lines.join("\n")}\n`;
}

export async function writeStepSummary(
  path: string | undefined,
  report: SynSecReport,
  baselineSource: string,
): Promise<void> {
  const target = path?.trim();
  if (!target) return;
  await appendFile(target, renderStepSummary(report, baselineSource), "utf8");
}
