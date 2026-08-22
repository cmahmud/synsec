import test from "node:test";
import assert from "node:assert/strict";

import { buildGitHubCheck, reportFailsThreshold } from "../packages/github/dist/index.js";

const report = {
  schemaVersion: "1.0",
  reportId: "threshold-none",
  generatedAt: "2026-08-22T16:00:00.000Z",
  toolVersion: "0.2.0",
  target: { path: ".", commitSha: "abcdef1234567890" },
  scanners: [{ scanner: "opengrep", startedAt: "a", completedAt: "b", findingCount: 1, artifactCount: 0, diagnostics: [] }],
  rawFindingCount: 1,
  findingCount: 1,
  summary: { critical: 1, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
  securityScore: 70,
  findings: [{
    fingerprint: "fp-critical",
    primary: {
      id: "critical",
      title: "Critical finding",
      description: "Evidence-backed critical repository finding.",
      category: "sast",
      severity: "critical",
      confidence: 0.99,
      scanner: { name: "opengrep", ruleId: "critical" },
      location: { path: "src/app.ts", startLine: 1 },
    },
    duplicates: [],
    sources: [{ name: "opengrep", ruleId: "critical" }],
  }],
  scope: { mode: "repository" },
};

test("failOn none never produces a failing GitHub conclusion", () => {
  assert.equal(reportFailsThreshold(report, "none"), false);
  const check = buildGitHubCheck(report, { repository: "cmahmud/synsec", sha: "abcdef1234567890" }, { threshold: "none" });
  assert.equal(check.conclusion, "neutral");
  assert.match(check.output.summary, /CI threshold: \*\*none\*\*/);
});
