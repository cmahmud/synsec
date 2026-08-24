import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defaultConfig } from "../packages/config/dist/index.js";
import {
  discoverChangedFiles,
  reportMeetsFailureThreshold,
  runScanEngine,
  sanitizeScanDiagnostics,
  scannerFailureMessage,
  scannerStatuses,
} from "../packages/engine/dist/index.js";
import { buildReport } from "../packages/report/dist/index.js";

const exec = promisify(execFile);

async function git(root, ...args) {
  return await exec("git", ["-C", root, ...args]);
}

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

test("unknown scanner identities are sanitized before status or aggregate error reporting", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-engine-status-test-"));
  const githubToken = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
  const configuredId = `${githubToken}\u001b[31m`;
  try {
    await writeFile(join(root, "README.md"), "fixture\n");
    const config = structuredClone(defaultConfig);
    config.scanners = [configuredId];

    const statuses = await scannerStatuses(config);
    const unknown = statuses.find((status) => status.selected);
    assert.ok(unknown);
    assert.doesNotMatch(unknown.id, new RegExp(githubToken));
    assert.doesNotMatch(unknown.displayName, new RegExp(githubToken));
    assert.equal(unknown.id.includes("\u001b"), false);
    assert.match(unknown.displayName, /\[REDACTED/);

    await assert.rejects(
      runScanEngine({ rootPath: root, config }),
      (error) => {
        const message = error instanceof Error ? error.message : String(error);
        assert.match(message, /No selected scanner engines are available/);
        assert.doesNotMatch(message, new RegExp(githubToken));
        assert.equal(message.includes("\u001b"), false);
        assert.match(message, /\[REDACTED/);
        return true;
      },
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("scanner failures are redacted before crossing the engine reporting boundary", () => {
  const githubToken = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
  const message = scannerFailureMessage(
    new Error(`scanner transport failed authorization: Bearer ${githubToken} via https://alice:password@example.invalid/api`),
  );

  assert.match(message, /scanner transport failed/);
  assert.doesNotMatch(message, new RegExp(githubToken));
  assert.doesNotMatch(message, /alice:password/);
  assert.match(message, /\[REDACTED/);
  assert.equal(scannerFailureMessage(new Error("\u0000\u0001")), "Scanner failed without an operational diagnostic.");
});

test("successful scanner diagnostics are redacted and bounded without changing findings", () => {
  const githubToken = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
  const finding = {
    id: "fixture",
    title: "Finding evidence remains scanner-owned",
    category: "sast",
    severity: "medium",
    confidence: 0.9,
    scanner: { name: "fixture" },
  };
  const scan = {
    scanner: "fixture",
    startedAt: "2026-01-01T00:00:00.000Z",
    completedAt: "2026-01-01T00:00:01.000Z",
    target: { path: "/repo" },
    findings: [finding],
    diagnostics: [
      `authorization: Bearer ${githubToken}`,
      "https://alice:password@example.invalid/scanner",
      ...Array.from({ length: 1_005 }, (_, index) => `diagnostic ${index}`),
    ],
  };

  const sanitized = sanitizeScanDiagnostics(scan);
  assert.equal(sanitized.findings[0], finding);
  assert.equal(sanitized.diagnostics.length, 1_001);
  assert.match(sanitized.diagnostics[0], /\[REDACTED\]/);
  assert.doesNotMatch(sanitized.diagnostics.join("\n"), new RegExp(githubToken));
  assert.doesNotMatch(sanitized.diagnostics.join("\n"), /alice:password/);
  assert.match(sanitized.diagnostics.at(-1), /omitted after 1000 entries/);
});

test("changed-file discovery returns repository-relative files from the requested base", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-changed-test-"));
  try {
    await git(root, "init");
    await git(root, "config", "user.name", "SynSec Test");
    await git(root, "config", "user.email", "synsec-test@example.invalid");

    await writeFile(join(root, "a.txt"), "first\n");
    await git(root, "add", "a.txt");
    await git(root, "commit", "-m", "first");

    await writeFile(join(root, "b.txt"), "second\n");
    await git(root, "add", "b.txt");
    await git(root, "commit", "-m", "second");

    const scope = await discoverChangedFiles(root, "HEAD~1");
    assert.equal(scope.base, "HEAD~1");
    assert.deepEqual(scope.files, ["b.txt"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("changed-file discovery rejects unsafe base revisions without reflecting attacker-controlled text", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-changed-base-test-"));
  const githubToken = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
  try {
    await git(root, "init");
    await git(root, "config", "user.name", "SynSec Test");
    await git(root, "config", "user.email", "synsec-test@example.invalid");
    await writeFile(join(root, "a.txt"), "fixture\n");
    await git(root, "add", "a.txt");
    await git(root, "commit", "-m", "fixture");

    for (const base of [`--output=${githubToken}`, `HEAD~1\n${githubToken}`]) {
      await assert.rejects(
        discoverChangedFiles(root, base),
        (error) => {
          const message = error instanceof Error ? error.message : String(error);
          assert.match(message, /base revision is invalid/);
          assert.doesNotMatch(message, new RegExp(githubToken));
          return true;
        },
      );
    }
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
