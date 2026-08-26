import { chmod, mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { SbomPackage } from "@synsec/core";
import type { SynSecReport } from "./index.js";

export interface SbomViewPackage {
  name: string;
  version?: string;
  type?: string;
  purl?: string;
  licenses: string[];
  locationCount: number;
}

export interface SbomView {
  schemaVersion: 1;
  reportId: string;
  packageCount: number;
  uniquePackageCount: number;
  packages: SbomViewPackage[];
  licenses: string[];
  producers: string[];
  /** Dependency inventory only; this view does not imply vulnerability or runtime reachability. */
  interpretation: "sbom-inventory-not-vulnerability-or-reachability";
}

const MAX_VIEW_PACKAGES = 100_000;

function packageKey(pkg: SbomPackage): string {
  return (pkg.purl?.trim() || `${pkg.type ?? ""}|${pkg.name}|${pkg.version ?? ""}`).toLowerCase();
}

export function buildSbomView(report: SynSecReport): SbomView {
  const artifacts = (report.artifacts ?? []).filter((artifact) => artifact.type === "sbom");
  const byPackage = new Map<string, SbomViewPackage>();
  let packageCount = 0;

  for (const artifact of artifacts) {
    packageCount += artifact.packages.length;
    for (const pkg of artifact.packages) {
      if (byPackage.size >= MAX_VIEW_PACKAGES && !byPackage.has(packageKey(pkg))) {
        throw new Error(`SBOM view exceeds the ${MAX_VIEW_PACKAGES}-package limit.`);
      }
      const key = packageKey(pkg);
      const existing = byPackage.get(key);
      const licenses = [...new Set([...(existing?.licenses ?? []), ...(pkg.licenses ?? [])].map((value) => value.trim()).filter(Boolean))].sort();
      const candidate: SbomViewPackage = {
        name: pkg.name,
        ...(pkg.version ? { version: pkg.version } : {}),
        ...(pkg.type ? { type: pkg.type } : {}),
        ...(pkg.purl ? { purl: pkg.purl } : {}),
        licenses,
        locationCount: Math.max(existing?.locationCount ?? 0, pkg.locations?.length ?? 0),
      };
      byPackage.set(key, candidate);
    }
  }

  const packages = [...byPackage.values()].sort((a, b) =>
    a.name.localeCompare(b.name) || (a.version ?? "").localeCompare(b.version ?? "") || (a.purl ?? "").localeCompare(b.purl ?? ""));
  const licenses = [...new Set(packages.flatMap((pkg) => pkg.licenses))].sort();
  const producers = [...new Set(artifacts.map((artifact) => artifact.producer.trim()).filter(Boolean))].sort();

  return {
    schemaVersion: 1,
    reportId: report.reportId,
    packageCount,
    uniquePackageCount: packages.length,
    packages,
    licenses,
    producers,
    interpretation: "sbom-inventory-not-vulnerability-or-reachability",
  };
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function renderSbomHtml(view: SbomView): string {
  const rows = view.packages.map((pkg) => `<tr>
<td>${escapeHtml(pkg.name)}</td>
<td>${escapeHtml(pkg.version ?? "—")}</td>
<td>${escapeHtml(pkg.type ?? "—")}</td>
<td>${pkg.purl ? `<code>${escapeHtml(pkg.purl)}</code>` : "—"}</td>
<td>${pkg.licenses.length ? escapeHtml(pkg.licenses.join(", ")) : "—"}</td>
<td>${pkg.locationCount}</td>
</tr>`).join("\n");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>SynSec dependency inventory</title>
<style>
:root{color-scheme:light dark;font-family:ui-sans-serif,system-ui,sans-serif}body{max-width:1400px;margin:0 auto;padding:24px;line-height:1.4}.muted{opacity:.7}.summary{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}.summary span{border:1px solid color-mix(in srgb,currentColor 24%,transparent);border-radius:10px;padding:8px 12px}.table{overflow:auto;border:1px solid color-mix(in srgb,currentColor 24%,transparent);border-radius:10px}table{width:100%;border-collapse:collapse;min-width:900px}th,td{text-align:left;padding:10px;border-bottom:1px solid color-mix(in srgb,currentColor 16%,transparent);vertical-align:top}th{position:sticky;top:0;background:Canvas}code{font-size:.78rem;overflow-wrap:anywhere}
</style>
</head>
<body>
<h1>SynSec dependency inventory</h1>
<p class=muted>SBOM inventory only · report ${escapeHtml(view.reportId)}</p>
<div class=summary>
  <span>${view.uniquePackageCount} unique packages</span>
  <span>${view.packageCount} artifact package records</span>
  <span>${view.licenses.length} observed licenses</span>
  <span>${view.producers.length} SBOM producers</span>
</div>
${rows ? `<div class=table><table><thead><tr><th>Package</th><th>Version</th><th>Type</th><th>PURL</th><th>Licenses</th><th>Locations</th></tr></thead><tbody>${rows}</tbody></table></div>` : "<p>No SBOM packages are present in this report.</p>"}
</body>
</html>\n`;
}

export async function writeSbomHtml(path: string, view: SbomView): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, renderSbomHtml(view), { encoding: "utf8", mode: 0o600 });
  await chmod(path, 0o600).catch(() => undefined);
}
