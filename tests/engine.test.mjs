import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defaultConfig } from "../packages/config/dist/index.js";
import { reportMeetsFailureThreshold, runScanEngine } from "../packages/engine/dist/index.js";
import { buildReport } from "../packages/report/dist/index.js";

test("scan engine refuses to produce a clean report when no selected scanner exists", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-engine-test-"));
  try {
    await writeFile(join(root, "README.md"), "fixture\n");
    const config = structuredClone(defaultConfig);
    config.scanners = ["scanner-that-does-not-exist"];
    await assert.rejects(
      runScanEngine({ rootPath: root, config }),
      /No selected scanner engines are available/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("failure threshold treats configured severity as inclusive", () => {
  const scan = {
    scanner: "fixture",
    startedAt: "2026-01-01T00:00:00.000Z",
    completedAt: "2026-01-01T00:00:01.000Z",
    target: { path: "/repo" },
    diagnostics: [],
    findings: [{
      id: "fixture",
      title: "Medium issue",
      category: "sast",
      severity: "medium",
      confidence: 0.9,
      scanner: { name: "fixture" },
    }],
  };
  const report = buildReport({ target: { path: "/repo" }, scans: [scan] });
  assert.equal(reportMeetsFailureThreshold(report, "high"), false);
  assert.equal(reportMeetsFailureThreshold(report, "medium"), true);
  assert.equal(reportMeetsFailureThreshold(report, "low"), true);
  assert.equal(reportMeetsFailureThreshold(report, "none"), false);
});
