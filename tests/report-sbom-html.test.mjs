import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { buildReport } from "@synsec/report";
import { buildSbomView, renderSbomHtml, writeSbomHtml } from "@synsec/report/sbom-html";

function report() {
  return buildReport({
    target: { path: "/repo", commitSha: "0123456789abcdef0123456789abcdef01234567" },
    scans: [{
      scanner: "syft",
      startedAt: "2026-08-22T19:00:00.000Z",
      completedAt: "2026-08-22T19:00:01.000Z",
      target: { path: "/repo" },
      findings: [],
      diagnostics: ["must not enter the dependency dashboard"],
      artifacts: [{
        type: "sbom",
        format: "syft-json",
        producer: "Syft <unsafe>",
        generatedAt: "2026-08-22T19:00:01.000Z",
        packageCount: 2,
        packages: [{
          name: "pkg<script>",
          version: "1.0.0",
          type: "npm",
          purl: "pkg:npm/pkg%3Cscript%3E@1.0.0",
          licenses: ["MIT", "Apache-2.0"],
          locations: ["package-lock.json", "node_modules/pkg/package.json"],
        }, {
          name: "duplicate-name",
          version: "2.0.0",
          type: "npm",
          purl: "pkg:npm/shared@2.0.0",
          licenses: ["MIT"],
          locations: ["package-lock.json"],
        }],
      }, {
        type: "sbom",
        format: "syft-json",
        producer: "second-producer",
        generatedAt: "2026-08-22T19:00:02.000Z",
        packageCount: 1,
        packages: [{
          name: "shared",
          version: "2.0.0",
          type: "npm",
          purl: "pkg:npm/shared@2.0.0",
          licenses: ["BSD-3-Clause"],
          locations: ["pnpm-lock.yaml", "src/unused-location"],
        }],
      }],
    }],
  });
}

test("SBOM view deduplicates package identity and exposes inventory semantics only", () => {
  const view = buildSbomView(report());
  assert.equal(view.packageCount, 3);
  assert.equal(view.uniquePackageCount, 2);
  assert.deepEqual(view.licenses, ["Apache-2.0", "BSD-3-Clause", "MIT"]);
  assert.deepEqual(view.producers, ["Syft <unsafe>", "second-producer"]);
  assert.equal(view.interpretation, "sbom-inventory-not-vulnerability-or-reachability");

  const shared = view.packages.find((pkg) => pkg.purl === "pkg:npm/shared@2.0.0");
  assert.deepEqual(shared.licenses, ["BSD-3-Clause", "MIT"]);
  assert.equal(shared.locationCount, 2);
});

test("SBOM HTML escapes package-controlled fields and omits scanner diagnostics/raw locations", () => {
  const html = renderSbomHtml(buildSbomView(report()));
  assert.match(html, /pkg&lt;script&gt;/);
  assert.equal(html.includes("pkg<script>"), false);
  assert.equal(html.includes("must not enter the dependency dashboard"), false);
  assert.equal(html.includes("src/unused-location"), false);
  assert.match(html, /SBOM inventory only/);
  assert.match(html, /<meta name="robots" content="noindex,nofollow">/);
});

test("SBOM HTML writer uses restrictive permissions where supported", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-sbom-html-"));
  const path = join(root, "dependency", "index.html");
  try {
    await writeSbomHtml(path, buildSbomView(report()));
    assert.match(await readFile(path, "utf8"), /SynSec dependency inventory/);
    if (process.platform !== "win32") assert.equal((await stat(path)).mode & 0o777, 0o600);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("SBOM view handles reports without dependency artifacts", () => {
  const empty = buildReport({
    target: { path: "/repo" },
    scans: [{
      scanner: "fixture",
      startedAt: "2026-08-22T19:00:00.000Z",
      completedAt: "2026-08-22T19:00:01.000Z",
      target: { path: "/repo" },
      findings: [],
      diagnostics: [],
    }],
  });
  const view = buildSbomView(empty);
  assert.equal(view.uniquePackageCount, 0);
  assert.match(renderSbomHtml(view), /No SBOM packages are present/);
});
