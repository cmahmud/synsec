import { chmod, mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { FindingTriageView } from "./triage-view.js";

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function stateLabel(value: string): string {
  return value.replaceAll("-", " ");
}

/**
 * Render a self-contained local finding-triage dashboard from the sanitized triage-view model.
 * The renderer has no access to repository source, scanner diagnostics, finding metadata, or tokens.
 */
export function renderFindingTriageHtml(view: FindingTriageView): string {
  const rows = view.items.map((item) => {
    const comments = item.comments.length === 0
      ? "<span class=muted>No review comments</span>"
      : `<ol>${item.comments.map((comment) => `<li><div>${escapeHtml(comment.body)}</div><small>${escapeHtml(comment.author ?? "unattributed")} · ${escapeHtml(comment.createdAt)}</small></li>`).join("")}</ol>`;
    return `<article>
      <header><strong>${escapeHtml(item.title)}</strong><span class=severity>${escapeHtml(item.severity)}</span></header>
      <dl>
        <div><dt>State</dt><dd>${escapeHtml(stateLabel(item.state))}</dd></div>
        <div><dt>Owner</dt><dd>${escapeHtml(item.owner ?? "unassigned")}</dd></div>
        <div><dt>Updated</dt><dd>${escapeHtml(item.updatedAt)}</dd></div>
        ${item.reviewAt ? `<div><dt>Review by</dt><dd>${escapeHtml(item.reviewAt)}</dd></div>` : ""}
      </dl>
      ${item.note ? `<p class=note>${escapeHtml(item.note)}</p>` : ""}
      <details><summary>Review comments (${item.comments.length})</summary>${comments}</details>
      <footer><code>${escapeHtml(item.fingerprint)}</code></footer>
    </article>`;
  }).join("\n");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>SynSec finding triage</title>
<style>
:root{color-scheme:light dark;font-family:ui-sans-serif,system-ui,sans-serif}body{max-width:1100px;margin:0 auto;padding:24px;line-height:1.45}h1{margin-bottom:4px}.summary{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}.summary span,article{border:1px solid color-mix(in srgb,currentColor 24%,transparent);border-radius:10px}.summary span{padding:8px 12px}article{padding:16px;margin:14px 0}article header{display:flex;justify-content:space-between;gap:16px}.severity{text-transform:uppercase;font-size:.85rem}dl{display:flex;gap:22px;flex-wrap:wrap}dl div{display:flex;gap:6px}dt{font-weight:600}.note{padding:10px;border-left:3px solid currentColor}ol{padding-left:24px}li{margin:10px 0}small,.muted,footer{opacity:.7}footer{margin-top:12px;overflow-wrap:anywhere}code{font-size:.78rem}summary{cursor:pointer}
</style>
</head>
<body>
<h1>SynSec finding triage</h1>
<p class=muted>Human triage metadata only · report ${escapeHtml(view.reportId)}</p>
<div class=summary>
  <span>${view.summary.current} current</span>
  <span>${view.summary.assigned} assigned</span>
  <span>${view.summary.unassigned} unassigned</span>
  <span>${view.summary.commented} commented</span>
</div>
${rows || "<p>No current lifecycle findings.</p>"}
</body>
</html>\n`;
}

export async function writeFindingTriageHtml(path: string, view: FindingTriageView): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, renderFindingTriageHtml(view), { encoding: "utf8", mode: 0o600 });
  await chmod(path, 0o600).catch(() => undefined);
}
