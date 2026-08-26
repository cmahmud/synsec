import { chmod, mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { RepositoryPostureSummary } from "./posture.js";

/** Render aggregate bounded lexical posture signals without source text or route paths. */
export function renderRepositoryPostureHtml(posture: RepositoryPostureSummary): string {
  const authObserved = posture.routeAuth["authorization-signal-observed"] + posture.routeAuth["authentication-signal-observed"];
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>SynSec repository posture</title>
<style>
:root{color-scheme:light dark;font-family:ui-sans-serif,system-ui,sans-serif}body{max-width:1050px;margin:0 auto;padding:24px;line-height:1.45}.muted{opacity:.72}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin:22px 0}.card{border:1px solid color-mix(in srgb,currentColor 24%,transparent);border-radius:12px;padding:16px}.value{font-size:2rem;font-weight:700}.section{margin-top:30px}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:10px;border-bottom:1px solid color-mix(in srgb,currentColor 16%,transparent)}
</style>
</head>
<body>
<h1>SynSec repository posture</h1>
<p class=muted>Bounded lexical repository signals only. These counts are prioritization evidence, not runtime exposure, data-flow reachability, or proof that authentication is present or absent at runtime.</p>
<div class=grid>
  <div class=card><div class=value>${posture.indexedFileCount}</div><div>indexed files</div></div>
  <div class=card><div class=value>${posture.routeCount}</div><div>route signals</div></div>
  <div class=card><div class=value>${authObserved}</div><div>routes with nearby auth signals</div></div>
  <div class=card><div class=value>${posture.routesWithoutAuthSignals}</div><div>routes with no nearby auth signal observed</div></div>
  <div class=card><div class=value>${posture.routesWithSinkSignals}</div><div>routes with nearby sink signals</div></div>
</div>
<section class=section>
<h2>Authentication / authorization proximity</h2>
<table><tbody>
<tr><th>Authorization signal observed</th><td>${posture.routeAuth["authorization-signal-observed"]}</td></tr>
<tr><th>Authentication signal observed</th><td>${posture.routeAuth["authentication-signal-observed"]}</td></tr>
<tr><th>No auth signal observed</th><td>${posture.routeAuth["no-auth-signal-observed"]}</td></tr>
</tbody></table>
</section>
<section class=section>
<h2>Nearby sink kinds</h2>
<table><tbody>
<tr><th>Process</th><td>${posture.routeSinkKinds.process}</td></tr>
<tr><th>Filesystem</th><td>${posture.routeSinkKinds.filesystem}</td></tr>
<tr><th>Database</th><td>${posture.routeSinkKinds.database}</td></tr>
<tr><th>Network</th><td>${posture.routeSinkKinds.network}</td></tr>
</tbody></table>
</section>
</body>
</html>\n`;
}

export async function writeRepositoryPostureHtml(path: string, posture: RepositoryPostureSummary): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, renderRepositoryPostureHtml(posture), { encoding: "utf8", mode: 0o600 });
  await chmod(path, 0o600).catch(() => undefined);
}
