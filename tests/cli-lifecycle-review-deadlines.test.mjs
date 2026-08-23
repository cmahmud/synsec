import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { writeLifecycleStore } from "@synsec/lifecycle";

const execFileAsync = promisify(execFile);

async function runCli(args) {
  return execFileAsync(process.execPath, ["apps/cli/dist/lifecycle-review-deadlines-cli.js", ...args], {
    cwd: process.cwd(),
    env: { ...process.env, NO_COLOR: "1" },
  });
}

function fixtureStore() {
  return {
    schemaVersion: 1,
    records: {
      overdue: {
        fingerprint: "overdue",
        state: "accepted-risk",
        updatedAt: "2026-08-01T00:00:00.000Z",
        reviewAt: "2026-08-20T00:00:00.000Z",
        note: "must never appear in governance output",
        owner: "security-team",
        lastSeenPath: "src/private.ts",
      },
      soon: {
        fingerprint: "soon",
        state: "false-positive",
        updatedAt: "2026-08-01T00:00:00.000Z",
        reviewAt: "2026-08-25T00:00:00.000Z",
      },
      unscheduled: {
        fingerprint: "unscheduled",
        state: "accepted-risk",
        updatedAt: "2026-08-01T00:00:00.000Z",
      },
      scannerState: {
        fingerprint: "scannerState",
        state: "confirmed",
        updatedAt: "2026-08-01T00:00:00.000Z",
        reviewAt: "2026-08-01T00:00:00.000Z",
      },
    },
  };
}

test("lifecycle review CLI emits minimized deterministic JSON", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-lifecycle-reviews-"));
  const storePath = join(root, "lifecycle.json");
  try {
    await writeLifecycleStore(storePath, fixtureStore());
    const result = await runCli([
      storePath,
      "--now", "2026-08-23T00:00:00.000Z",
      "--due-soon-days", "3",
      "--json",
    ]);
    const assessment = JSON.parse(result.stdout);
    assert.deepEqual(assessment.summary, {
      reviewable: 3,
      unscheduled: 1,
      overdue: 1,
      dueSoon: 1,
      scheduled: 0,
    });
    assert.deepEqual(assessment.items.map((item) => item.fingerprint), ["overdue", "soon"]);
    assert.doesNotMatch(result.stdout, /must never appear/);
    assert.doesNotMatch(result.stdout, /security-team/);
    assert.doesNotMatch(result.stdout, /src\/private\.ts/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("lifecycle review CLI summary-only JSON omits paths, fingerprints, and review timestamps", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-lifecycle-review-summary-"));
  const storePath = join(root, "private-lifecycle.json");
  try {
    await writeLifecycleStore(storePath, fixtureStore());
    const result = await runCli([
      storePath,
      "--now", "2026-08-23T00:00:00.000Z",
      "--due-soon-days", "3",
      "--summary-only",
      "--json",
    ]);
    const summary = JSON.parse(result.stdout);
    assert.equal(summary.ready, true);
    assert.deepEqual(summary.violations, []);
    assert.deepEqual(summary.summary, {
      reviewable: 3,
      overdue: 1,
      dueSoon: 1,
      scheduled: 0,
      unscheduled: 1,
    });
    assert.doesNotMatch(result.stdout, /private-lifecycle|"fingerprint"|"reviewAt"|"overdue"\s*:\s*"/);
    assert.doesNotMatch(result.stdout, /must never appear|security-team|src\/private\.ts/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("lifecycle review CLI has distinct policy exit codes", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-lifecycle-review-policy-"));
  const storePath = join(root, "lifecycle.json");
  try {
    await writeLifecycleStore(storePath, fixtureStore());

    await assert.rejects(
      runCli([storePath, "--now", "2026-08-23T00:00:00.000Z", "--fail-overdue"]),
      (error) => error?.code === 2,
    );
    await assert.rejects(
      runCli([storePath, "--now", "2026-08-19T00:00:00.000Z", "--fail-unscheduled"]),
      (error) => error?.code === 3,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("lifecycle review CLI rejects unsupported options without echoing values", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-lifecycle-review-options-"));
  const storePath = join(root, "lifecycle.json");
  try {
    await writeLifecycleStore(storePath, fixtureStore());
    await assert.rejects(
      runCli([storePath, "--database-url=postgres://user:super-secret@example.invalid/db"]),
      (error) => {
        assert.equal(error?.code, 1);
        assert.doesNotMatch(error?.stderr ?? "", /super-secret/);
        return true;
      },
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
