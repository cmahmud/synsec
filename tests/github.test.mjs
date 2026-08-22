import test from "node:test";
import assert from "node:assert/strict";

import {
  buildGitHubAnnotations,
  buildGitHubCheck,
  detectGitHubContext,
  reportFailsThreshold,
} from "../packages/github/dist/index.js";

function report(overrides = {}) {
  const finding = {
    fingerprint: "fp-high",
    primary: {
      id: "f-1",
      title: "Unsafe deserialization",
      description: "Untrusted input reaches a deserializer.\nReview the data boundary.",
      category: "sast",
      severity: "high",
      confidence: 0.96,
      scanner: { name: "opengrep", ruleId: "unsafe-deserialize" },
      location: { path: "./src\\handler.ts", startLine: 14, endLine: 16 },
      remediation: "Use a typed parser and validate the payload before decoding.",
    },
    duplicates: [],
    sources: [{ name: "opengrep", ruleId: "unsafe-deserialize" }],
  };

  return {
    schemaVersion: "1.0",
    reportId: "report-1",
    generatedAt: "2026-08-22T12:00:00.000Z",
    toolVersion: "0.2.0",
    target: { path: ".", commitSha: "abc123" },
    scanners: [{ scanner: "opengrep", startedAt: "a", completedAt: "b", findingCount: 1, artifactCount: 0, diagnostics: [] }],
    rawFindingCount: 1,
    findingCount: 1,
    summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0, unknown: 0 },
    securityScore: 88,
    findings: [finding],
    scope: { mode: "changed-files", baseRef: "main", changedFiles: ["src/handler.ts"] },
    baseline: { new: ["fp-high"], fixed: [], persisting: [] },
    ...overrides,
  };
}

test("detectGitHubContext extracts safe repository and pull-request metadata", () => {
  assert.deepEqual(
    detectGitHubContext({
      GITHUB_REPOSITORY: "cmahmud/synsec",
      GITHUB_SHA: "abc123",
      GITHUB_REF: "refs/pull/42/merge",
      GITHUB_BASE_REF: "main",
      GITHUB_HEAD_REF: "feature/security",
    }),
    {
      repository: "cmahmud/synsec",
      sha: "abc123",
      ref: "refs/pull/42/merge",
      baseRef: "main",
      headRef: "feature/security",
      pullRequestNumber: 42,
    },
  );

  assert.equal(detectGitHubContext({ GITHUB_REPOSITORY: "bad repo", GITHUB_SHA: "abc" }), undefined);
});

test("pull-request event payload overrides the synthetic merge SHA", () => {
  const context = detectGitHubContext(
    {
      GITHUB_REPOSITORY: "cmahmud/synsec",
      GITHUB_SHA: "synthetic-merge-sha",
      GITHUB_REF: "refs/pull/42/merge",
      GITHUB_BASE_REF: "stale-base",
      GITHUB_HEAD_REF: "stale-head",
    },
    {
      repository: { full_name: "cmahmud/synsec" },
      pull_request: {
        number: 42,
        head: { sha: "real-head-sha", ref: "feature/security" },
        base: { ref: "main" },
      },
    },
  );

  assert.equal(context.sha, "real-head-sha");
  assert.equal(context.pullRequestNumber, 42);
  assert.equal(context.baseRef, "main");
  assert.equal(context.headRef, "feature/security");
});

test("push payload can supply repository and after SHA", () => {
  assert.deepEqual(
    detectGitHubContext({}, {
      repository: { full_name: "cmahmud/synsec" },
      after: "push-head",
      ref: "refs/heads/main",
    }),
    { repository: "cmahmud/synsec", sha: "push-head", ref: "refs/heads/main" },
  );
});

test("GitHub annotations normalize paths, collapse newlines, and use severity levels", () => {
  const [annotation] = buildGitHubAnnotations(report());
  assert.equal(annotation.path, "src/handler.ts");
  assert.equal(annotation.start_line, 14);
  assert.equal(annotation.end_line, 16);
  assert.equal(annotation.annotation_level, "failure");
  assert.equal(annotation.message.includes("\n"), false);
  assert.match(annotation.raw_details, /SynSec fingerprint: fp-high/);
});

test("baseline mode annotates new findings only", () => {
  const base = report();
  const oldFinding = {
    ...base.findings[0],
    fingerprint: "fp-old",
    primary: { ...base.findings[0].primary, id: "f-2", title: "Persisting finding", location: { path: "src/old.ts", startLine: 2 } },
  };
  const withPersisting = {
    ...base,
    findingCount: 2,
    findings: [...base.findings, oldFinding],
    baseline: { new: ["fp-high"], fixed: [], persisting: ["fp-old"] },
  };
  assert.equal(buildGitHubAnnotations(withPersisting, { onlyNew: true }).length, 1);
  assert.equal(buildGitHubAnnotations(withPersisting, { onlyNew: false }).length, 2);
});

test("check result respects configured severity threshold", () => {
  const context = { repository: "cmahmud/synsec", sha: "abc123" };
  assert.equal(reportFailsThreshold(report(), "high"), true);
  assert.equal(reportFailsThreshold(report(), "critical"), false);

  const failed = buildGitHubCheck(report(), context, { threshold: "high" });
  assert.equal(failed.conclusion, "failure");
  assert.equal(failed.headSha, "abc123");
  assert.match(failed.output.summary, /New: \*\*1\*\*/);

  const neutral = buildGitHubCheck(report(), context, { threshold: "critical" });
  assert.equal(neutral.conclusion, "neutral");
});

test("annotation count is hard-capped to GitHub's per-request maximum", () => {
  const base = report();
  const findings = Array.from({ length: 75 }, (_, index) => ({
    ...base.findings[0],
    fingerprint: `fp-${index}`,
    primary: {
      ...base.findings[0].primary,
      id: `f-${index}`,
      location: { path: `src/${index}.ts`, startLine: index + 1 },
    },
  }));
  assert.equal(buildGitHubAnnotations({ ...base, findings, findingCount: findings.length }, { onlyNew: false, maxAnnotations: 999 }).length, 50);
});
