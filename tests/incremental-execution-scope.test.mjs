import assert from "node:assert/strict";
import test from "node:test";
import { buildReport } from "../packages/report/dist/index.js";
import { scannerSupportsNativeChangedFiles } from "../packages/scanners/dist/index.js";

const interpretation = "scanner-execution-scope-not-coverage-proof";

test("built-in scanner changed-file execution classification is conservative", () => {
  for (const scanner of ["opengrep", "betterleaks", "gitleaks", "checkov", "trivy", "osv-scanner"]) {
    assert.equal(scannerSupportsNativeChangedFiles(scanner), true, scanner);
  }
  for (const scanner of ["grype", "syft", "scorecard", "unknown-scanner"]) {
    assert.equal(scannerSupportsNativeChangedFiles(scanner), false, scanner);
  }
});

test("report scanner summaries preserve machine-readable execution scope", () => {
  const report = buildReport({
    target: { path: "/repo" },
    scope: { mode: "changed-files", baseRef: "base", changedFiles: ["src/a.ts"] },
    scans: [
      {
        scanner: "opengrep",
        startedAt: "2026-01-01T00:00:00.000Z",
        completedAt: "2026-01-01T00:00:01.000Z",
        target: { path: "/repo" },
        findings: [],
        diagnostics: [],
        executionScope: {
          mode: "changed-files-native",
          changedFileCount: 1,
          interpretation,
        },
      },
      {
        scanner: "syft",
        startedAt: "2026-01-01T00:00:00.000Z",
        completedAt: "2026-01-01T00:00:01.000Z",
        target: { path: "/repo" },
        findings: [],
        diagnostics: [],
        executionScope: {
          mode: "repository-then-filtered",
          changedFileCount: 1,
          interpretation,
        },
      },
    ],
  });

  assert.deepEqual(report.scanners.map((scanner) => [scanner.scanner, scanner.executionScope]), [
    ["opengrep", { mode: "changed-files-native", changedFileCount: 1, interpretation }],
    ["syft", { mode: "repository-then-filtered", changedFileCount: 1, interpretation }],
  ]);
  assert.equal(report.scope.mode, "changed-files");
});

test("execution scope remains optional for legacy and imported scan results", () => {
  const report = buildReport({
    target: { path: "/repo" },
    scans: [{
      scanner: "legacy",
      startedAt: "2026-01-01T00:00:00.000Z",
      completedAt: "2026-01-01T00:00:01.000Z",
      target: { path: "/repo" },
      findings: [],
      diagnostics: [],
    }],
  });
  assert.equal(report.scanners[0].executionScope, undefined);
});
