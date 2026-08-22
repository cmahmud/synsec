import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { FindingTriageView } from "@synsec/lifecycle/triage-view";
import { writeFindingTriageHtml } from "@synsec/lifecycle/triage-html";
import type { SynSecReport } from "@synsec/report";
import type { ReportHistory } from "@synsec/report/history";
import { writeHistoryHtml } from "@synsec/report/history-html";
import { buildSbomView, writeSbomHtml } from "@synsec/report/sbom-html";
import type { RepositoryPostureSummary } from "@synsec/repository/posture";
import { writeRepositoryPostureHtml } from "@synsec/repository/posture-html";

export interface ProjectDashboardInput {
  report: SynSecReport;
  triage: FindingTriageView;
  posture: RepositoryPostureSummary;
  history?: ReportHistory;
}

export interface ProjectDashboardPaths {
  directory: string;
  index: string;
  triage: string;
  dependencies: string;
  posture: string;
  history?: string;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function renderProjectDashboardIndex(input: ProjectDashboardInput): string {
  const sbom = buildSbomView(input.report);
  const summary = input.report.summary;
  const historyCard = input.history
    ? `<a class=card href="history.html" aria-label="${input.history.points.length} historical scans, score delta ${input.history.scoreDelta >= 0 ? "+" : ""}${input.history.scoreDelta}"><div class=value>${input.history.points.length}</div><div>historical scans</div><small>score delta ${input.history.scoreDelta >= 0 ? "+" : ""}${input.history.scoreDelta}</small></a>`
    : "";
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>SynSec project dashboard</title>
<style>
:root{color-scheme:light dark;font-family:ui-sans-serif,system-ui,sans-serif}body{max-width:1100px;margin:0 auto;padding:24px;line-height:1.45}.muted{opacity:.72}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin:22px 0}.card{display:block;color:inherit;text-decoration:none;border:1px solid color-mix(in srgb,currentColor 24%,transparent);border-radius:12px;padding:18px}.card:hover{outline:2px solid currentColor}.value{font-size:2rem;font-weight:700}.severity{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}.severity span{border:1px solid color-mix(in srgb,currentColor 18%,transparent);border-radius:999px;padding:5px 9px}code{font-size:.8rem;overflow-wrap:anywhere}
</style>
</head>
<body>
<h1>SynSec project dashboard</h1>
<p class=muted>Local sanitized security views · report <code>${escapeHtml(input.report.reportId)}</code></p>
<div class=grid>
  <a class=card href="triage.html"><div class=value>${input.triage.summary.current}</div><div>current lifecycle findings</div><small>${input.triage.summary.assigned} assigned · ${input.triage.summary.commented} commented</small></a>
  <a class=card href="dependencies.html"><div class=value>${sbom.uniquePackageCount}</div><div>unique SBOM packages</div><small>${sbom.licenses.length} observed licenses</small></a>
  <a class=card href="posture.html"><div class=value>${input.posture.routeCount}</div><div>bounded route signals</div><small>${input.posture.routesWithSinkSignals} with nearby sink signals</small></a>
  ${historyCard}
  <div class=card><div class=value>${input.report.securityScore}</div><div>security score</div><small>${input.report.findingCount} correlated findings</small></div>
</div>
<div class=severity>
  <span>${summary.critical} critical</span><span>${summary.high} high</span><span>${summary.medium} medium</span><span>${summary.low} low</span><span>${summary.info} info</span><span>${summary.unknown} unknown</span>
</div>
<p class=muted>This index links only to locally generated sanitized views. Repository source excerpts, scanner diagnostics, tokens, and arbitrary outbound URLs are not embedded by this dashboard composition.</p>
</body>
</html>\n`;
}

/**
 * Write one local static project dashboard bundle from already-normalized SynSec models.
 *
 * The bundle has no server, authentication, remote assets, JavaScript, source excerpts, or scanner
 * credentials. It is a developer-facing local composition primitive, not the future multi-user web
 * application. Optional history is accepted only through the existing trend-safe history model.
 * All generated files are written with restrictive permissions where supported.
 */
export async function writeProjectDashboard(
  directory: string,
  input: ProjectDashboardInput,
): Promise<ProjectDashboardPaths> {
  const root = resolve(directory);
  await mkdir(root, { recursive: true, mode: 0o700 });
  const paths: ProjectDashboardPaths = {
    directory: root,
    index: join(root, "index.html"),
    triage: join(root, "triage.html"),
    dependencies: join(root, "dependencies.html"),
    posture: join(root, "posture.html"),
    ...(input.history ? { history: join(root, "history.html") } : {}),
  };

  const writes: Promise<unknown>[] = [
    writeFile(paths.index, renderProjectDashboardIndex(input), { encoding: "utf8", mode: 0o600 })
      .then(() => chmod(paths.index, 0o600).catch(() => undefined)),
    writeFindingTriageHtml(paths.triage, input.triage),
    writeSbomHtml(paths.dependencies, buildSbomView(input.report)),
    writeRepositoryPostureHtml(paths.posture, input.posture),
  ];
  if (input.history && paths.history) {
    writes.push(writeHistoryHtml(paths.history, input.history, { title: "SynSec project security history" }));
  }
  await Promise.all(writes);

  return paths;
}
