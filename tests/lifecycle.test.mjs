import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildReport } from "../packages/report/dist/index.js";
import {
  emptyLifecycleStore,
  isLifecycleStore,
  lifecycleSummary,
  readLifecycleStore,
  reconcileLifecycle,
  setFindingOwner,
  setFindingState,
  verifyRemediation,
  writeLifecycleStore,
} from "../packages/lifecycle/dist/index.js";

function reportWith(ruleIds, options = {}) {
  return buildReport({
    target: { path: "/repo" },
    scans: [{
      scanner: options.scanner ?? "fixture",
      startedAt: "2026-01-01T00:00:00.000Z",
      completedAt: "2026-01-01T00:00:01.000Z",
      target: { path: "/repo" },
      diagnostics: [],
      findings: ruleIds.map((ruleId) => ({
        id: ruleId,
        title: `Finding ${ruleId}`,
        category: "sast",
        severity: "high",
        confidence: 1,
        scanner: { name: options.scanner ?? "fixture", ruleId },
        location: { path: `src/${ruleId}.ts`, startLine: 1 },
      })),
    }],
    scope: options.scope ?? { mode: "repository" },
  });
}

test("lifecycle creates new findings and preserves explicit triage state", () => {
  const report = reportWith(["A"]);
  let store = reconcileLifecycle(report, emptyLifecycleStore(), "2026-01-01T00:00:00.000Z");
  const fingerprint = report.findings[0].fingerprint;
  assert.equal(store.records[fingerprint].state, "new");
  assert.equal(store.records[fingerprint].lastSeenPath, "src/A.ts");

  store = setFindingState(store, fingerprint, "confirmed", {
    note: "Reviewed by maintainer",
    reportId: report.reportId,
    updatedAt: "2026-01-02T00:00:00.000Z",
  });
  assert.equal(store.records[fingerprint].lastSeenPath, "src/A.ts");
  const next = reconcileLifecycle(report, store, "2026-01-03T00:00:00.000Z");
  assert.equal(next.records[fingerprint].state, "confirmed");
  assert.equal(next.records[fingerprint].note, "Reviewed by maintainer");
});

test("finding ownership is bounded triage metadata and survives state/reconciliation changes", () => {
  const report = reportWith(["A"]);
  const fingerprint = report.findings[0].fingerprint;
  let store = reconcileLifecycle(report, emptyLifecycleStore(), "2026-01-01T00:00:00.000Z");
  store = setFindingOwner(store, fingerprint, "security-team", "2026-01-01T12:00:00.000Z");
  assert.equal(store.records[fingerprint].owner, "security-team");
  assert.equal(store.records[fingerprint].updatedAt, "2026-01-01T12:00:00.000Z");

  store = setFindingState(store, fingerprint, "confirmed", { updatedAt: "2026-01-02T00:00:00.000Z" });
  assert.equal(store.records[fingerprint].owner, "security-team");
  const next = reconcileLifecycle(report, store, "2026-01-03T00:00:00.000Z");
  assert.equal(next.records[fingerprint].owner, "security-team");

  const cleared = setFindingOwner(next, fingerprint, "", "2026-01-04T00:00:00.000Z");
  assert.equal(cleared.records[fingerprint].owner, undefined);
  assert.equal(cleared.records[fingerprint].state, "confirmed");
});

test("finding ownership rejects unknown records, control characters, oversized values, and invalid timestamps", () => {
  const report = reportWith(["A"]);
  const fingerprint = report.findings[0].fingerprint;
  const store = reconcileLifecycle(report, emptyLifecycleStore());
  assert.throws(() => setFindingOwner(store, "missing", "team"), /does not exist/);
  assert.throws(() => setFindingOwner(store, fingerprint, "team\nother"), /control line breaks/);
  assert.throws(() => setFindingOwner(store, fingerprint, "x".repeat(256)), /at most 255/);
  assert.throws(() => setFindingOwner(store, fingerprint, "team", "not-a-time"), /valid timestamp/);
});

test("lifecycle store validation rejects malformed record shapes", () => {
  assert.equal(isLifecycleStore({ schemaVersion: 1, records: {} }), true);
  assert.equal(isLifecycleStore({
    schemaVersion: 1,
    records: {
      abc: { fingerprint: "different", state: "new", updatedAt: "2026-01-01T00:00:00.000Z" },
    },
  }), false);
  assert.equal(isLifecycleStore({
    schemaVersion: 1,
    records: {
      abc: { fingerprint: "abc", state: "unknown", updatedAt: "2026-01-01T00:00:00.000Z" },
    },
  }), false);
  assert.equal(isLifecycleStore({
    schemaVersion: 1,
    records: {
      abc: { fingerprint: "abc", state: "new", updatedAt: "not-a-date" },
    },
  }), false);
  assert.equal(isLifecycleStore({
    schemaVersion: 1,
    records: {
      abc: { fingerprint: "abc", state: "new", updatedAt: "2026-01-01T00:00:00.000Z", owner: "bad\nowner" },
    },
  }), false);
});

test("lifecycle persistence is restrictive, round-trippable, and rejects corrupt stores", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-lifecycle-"));
  const path = join(root, "state", "lifecycle.json");
  try {
    const report = reportWith(["A"]);
    const fingerprint = report.findings[0].fingerprint;
    let store = reconcileLifecycle(report, emptyLifecycleStore(), "2026-01-01T00:00:00.000Z");
    store = setFindingOwner(store, fingerprint, "appsec");
    await writeLifecycleStore(path, store);
    assert.deepEqual(await readLifecycleStore(path), store);
    const serialized = await readFile(path, "utf8");
    assert.equal(JSON.parse(serialized).schemaVersion, 1);
    assert.equal(JSON.parse(serialized).records[fingerprint].owner, "appsec");
    if (process.platform !== "win32") assert.equal((await stat(path)).mode & 0o777, 0o600);

    await writeFile(path, JSON.stringify({
      schemaVersion: 1,
      records: { bad: { fingerprint: "mismatch", state: "new", updatedAt: "2026-01-01T00:00:00.000Z" } },
    }));
    await assert.rejects(() => readLifecycleStore(path), /Not a supported SynSec lifecycle store/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("lifecycle marks disappeared confirmed findings fixed and returning findings regressed", () => {
  const initial = reportWith(["A"]);
  const fingerprint = initial.findings[0].fingerprint;
  let store = reconcileLifecycle(initial, emptyLifecycleStore(), "2026-01-01T00:00:00.000Z");
  store = setFindingState(store, fingerprint, "confirmed", { updatedAt: "2026-01-02T00:00:00.000Z" });

  const fixed = reconcileLifecycle(reportWith([]), store, "2026-01-03T00:00:00.000Z");
  assert.equal(fixed.records[fingerprint].state, "fixed");

  const regressed = reconcileLifecycle(initial, fixed, "2026-01-04T00:00:00.000Z");
  assert.equal(regressed.records[fingerprint].state, "regressed");
  assert.equal(lifecycleSummary(regressed).regressed, 1);
});

test("changed-file scans do not mark out-of-scope findings fixed", () => {
  const initial = reportWith(["A", "B"]);
  const [a, b] = initial.findings.map((finding) => finding.fingerprint);
  let store = reconcileLifecycle(initial, emptyLifecycleStore(), "2026-01-01T00:00:00.000Z");
  store = setFindingState(store, a, "confirmed", { updatedAt: "2026-01-02T00:00:00.000Z" });
  store = setFindingState(store, b, "confirmed", { updatedAt: "2026-01-02T00:00:00.000Z" });

  const incremental = reportWith([], {
    scope: { mode: "changed-files", baseRef: "main", changedFiles: ["src/A.ts"] },
  });
  const next = reconcileLifecycle(incremental, store, "2026-01-03T00:00:00.000Z");
  assert.equal(next.records[a].state, "fixed");
  assert.equal(next.records[b].state, "confirmed");
  assert.equal(next.records[b].reportId, store.records[b].reportId);
});

test("false-positive and accepted-risk decisions are not rewritten just because a later scan omits the finding", () => {
  const report = reportWith(["A", "B"]);
  const [a, b] = report.findings.map((finding) => finding.fingerprint);
  let store = reconcileLifecycle(report, emptyLifecycleStore());
  store = setFindingState(store, a, "false-positive");
  store = setFindingState(store, b, "accepted-risk");

  const next = reconcileLifecycle(reportWith([]), store);
  assert.equal(next.records[a].state, "false-positive");
  assert.equal(next.records[b].state, "accepted-risk");
});

test("remediation verification only calls a missing finding fixed when detecting coverage was repeated", () => {
  const before = reportWith(["A"]);
  const fingerprint = before.findings[0].fingerprint;
  const after = reportWith([]);
  const verification = verifyRemediation(before, after, [fingerprint], "2026-01-02T00:00:00.000Z");
  assert.equal(verification.items[0].status, "fixed");
  assert.equal(verification.summary.fixed, 1);
});

test("remediation verification is inconclusive when the detecting scanner did not rerun", () => {
  const before = reportWith(["A"], { scanner: "fixture" });
  const after = reportWith([], { scanner: "different-scanner" });
  const verification = verifyRemediation(before, after);
  assert.equal(verification.items[0].status, "inconclusive");
  assert.match(verification.items[0].reasons.join(" "), /None of the scanner/);
});

test("changed-file verification is inconclusive when the affected path was outside the rescan scope", () => {
  const before = reportWith(["A"]);
  const after = reportWith([], {
    scope: { mode: "changed-files", baseRef: "main", changedFiles: ["src/B.ts"] },
  });
  const verification = verifyRemediation(before, after);
  assert.equal(verification.items[0].status, "inconclusive");
  assert.match(verification.items[0].reasons.join(" "), /did not scan the finding path/);
});

test("remediation verification reports persisting and newly introduced findings", () => {
  const before = reportWith(["A"]);
  const after = reportWith(["A", "B"]);
  const verification = verifyRemediation(before, after);
  assert.equal(verification.items[0].status, "persisting");
  assert.equal(verification.summary.persisting, 1);
  assert.equal(verification.summary.newFindings, 1);
  assert.equal(verification.newFindings.length, 1);
});
