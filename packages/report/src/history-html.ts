import type { ReportHistory, ReportHistoryPoint } from "./history.js";

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function signed(value: number): string {
  return value > 0 ? `+${value}` : String(value);
}

function dateLabel(value: string): string {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toISOString().slice(0, 10) : value;
}

function chartPoints(points: readonly ReportHistoryPoint[], width: number, height: number): string {
  if (points.length === 0) return "";
  const padding = 18;
  const usableWidth = Math.max(1, width - padding * 2);
  const usableHeight = Math.max(1, height - padding * 2);
  return points.map((point, index) => {
    const x = points.length === 1 ? width / 2 : padding + (index / (points.length - 1)) * usableWidth;
    const y = padding + ((100 - Math.max(0, Math.min(100, point.securityScore))) / 100) * usableHeight;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
}

function latestPoint(history: ReportHistory): ReportHistoryPoint | undefined {
  return history.points.at(-1);
}

export function renderHistoryHtml(history: ReportHistory, options: { title?: string } = {}): string {
  const title = escapeHtml(options.title?.trim() || "SynSec security history");
  const latest = latestPoint(history);
  const activeFindings = history.findings.filter((finding) => finding.presentInLatest);
  const trendRows = history.points.slice().reverse().map((point) => `
      <tr>
        <td>${escapeHtml(dateLabel(point.generatedAt))}</td>
        <td>${point.securityScore}</td>
        <td>${point.findingCount}</td>
        <td>${point.newCount}</td>
        <td>${point.fixedCount}</td>
        <td>${point.persistingCount}</td>
        <td>${escapeHtml(point.commitSha?.slice(0, 12) ?? "—")}</td>
      </tr>`).join("");
  const findingRows = activeFindings.slice(0, 100).map((finding) => `
      <tr>
        <td><span class="severity ${escapeHtml(finding.highestSeverity)}">${escapeHtml(finding.highestSeverity)}</span></td>
        <td>${escapeHtml(finding.title)}</td>
        <td>${finding.occurrenceCount}</td>
        <td>${escapeHtml(dateLabel(finding.firstSeenAt))}</td>
        <td>${escapeHtml(dateLabel(finding.lastSeenAt))}</td>
      </tr>`).join("");
  const polyline = chartPoints(history.points, 760, 180);

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${title}</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; background:#0b1020; color:#edf2f7; }
    * { box-sizing:border-box; }
    body { margin:0; background:#0b1020; color:#edf2f7; }
    main { width:min(1180px, calc(100% - 32px)); margin:32px auto 56px; }
    h1,h2 { margin:0; } h1 { font-size:30px; } h2 { font-size:18px; margin-bottom:14px; }
    .muted { color:#9aa7bd; }
    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin:24px 0; }
    .card,.panel { background:#121a2c; border:1px solid #26334d; border-radius:12px; }
    .card { padding:16px; } .card strong { display:block; font-size:28px; margin-top:5px; }
    .panel { padding:18px; margin-top:16px; overflow:auto; }
    svg { width:100%; min-width:520px; height:auto; background:#0d1424; border-radius:8px; }
    .gridline { stroke:#26334d; stroke-width:1; } .scoreline { fill:none; stroke:#7dd3fc; stroke-width:3; }
    table { width:100%; border-collapse:collapse; font-size:14px; }
    th,td { text-align:left; padding:10px 9px; border-bottom:1px solid #26334d; vertical-align:top; }
    th { color:#9aa7bd; font-weight:600; }
    .severity { text-transform:uppercase; font-size:11px; font-weight:800; letter-spacing:.04em; }
    .critical,.high { color:#fca5a5; } .medium { color:#fde68a; } .low,.info,.unknown { color:#bfdbfe; }
    .empty { color:#9aa7bd; padding:16px 0; }
  </style>
</head>
<body><main>
  <h1>${title}</h1>
  <p class="muted">Trend-safe repository security history. No source excerpts or scanner diagnostics are embedded in this dashboard.</p>
  <section class="grid">
    <div class="card"><span class="muted">Latest score</span><strong>${latest?.securityScore ?? "—"}${latest ? "/100" : ""}</strong></div>
    <div class="card"><span class="muted">Active findings</span><strong>${latest?.findingCount ?? 0}</strong></div>
    <div class="card"><span class="muted">Score change</span><strong>${signed(history.scoreDelta)}</strong></div>
    <div class="card"><span class="muted">Finding change</span><strong>${signed(history.findingCountDelta)}</strong></div>
  </section>
  <section class="panel"><h2>Security score</h2>
    ${history.points.length ? `<svg viewBox="0 0 760 180" role="img" aria-label="Security score trend">
      <line class="gridline" x1="18" y1="18" x2="742" y2="18"/><line class="gridline" x1="18" y1="90" x2="742" y2="90"/><line class="gridline" x1="18" y1="162" x2="742" y2="162"/>
      <polyline class="scoreline" points="${polyline}"/>
    </svg>` : `<div class="empty">No scan history is available yet.</div>`}
  </section>
  <section class="panel"><h2>Scan history</h2>
    ${history.points.length ? `<table><thead><tr><th>Date</th><th>Score</th><th>Findings</th><th>New</th><th>Fixed</th><th>Persisting</th><th>Commit</th></tr></thead><tbody>${trendRows}</tbody></table>` : `<div class="empty">No scans recorded.</div>`}
  </section>
  <section class="panel"><h2>Findings present in latest scan</h2>
    ${activeFindings.length ? `<table><thead><tr><th>Severity</th><th>Finding</th><th>Occurrences</th><th>First seen</th><th>Last seen</th></tr></thead><tbody>${findingRows}</tbody></table>` : `<div class="empty">No findings are present in the latest scan.</div>`}
  </section>
</main></body></html>`;
}
