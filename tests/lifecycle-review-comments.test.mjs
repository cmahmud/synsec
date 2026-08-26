import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  addFindingReviewComment,
  commentsForFinding,
  emptyFindingReviewCommentStore,
  isFindingReviewCommentStore,
  readFindingReviewCommentStore,
  writeFindingReviewCommentStore,
} from "@synsec/lifecycle/review-comments";

const fingerprint = "sha256:finding-1";
const timestamp = "2026-08-22T19:05:00.000Z";

test("review comments are append-only deterministic triage metadata", () => {
  const empty = emptyFindingReviewCommentStore();
  const first = addFindingReviewComment(empty, fingerprint, "Reviewed with the service owner.", {
    author: "security-team",
    createdAt: timestamp,
  });
  assert.equal(empty.comments[fingerprint], undefined);
  assert.equal(first.comments[fingerprint].length, 1);
  assert.equal(first.comments[fingerprint][0].body, "Reviewed with the service owner.");
  assert.equal(first.comments[fingerprint][0].author, "security-team");

  const duplicate = addFindingReviewComment(first, fingerprint, "Reviewed with the service owner.", {
    author: "security-team",
    createdAt: timestamp,
  });
  assert.equal(duplicate, first);

  const second = addFindingReviewComment(first, fingerprint, "Follow-up review complete.", {
    createdAt: "2026-08-22T19:06:00.000Z",
  });
  assert.deepEqual(commentsForFinding(second, fingerprint).map((comment) => comment.body), [
    "Reviewed with the service owner.",
    "Follow-up review complete.",
  ]);
});

test("review comment validation rejects malformed or oversized metadata", () => {
  const empty = emptyFindingReviewCommentStore();
  assert.throws(() => addFindingReviewComment(empty, "", "comment"), /fingerprint/);
  assert.throws(() => addFindingReviewComment(empty, fingerprint, ""), /review comment/);
  assert.throws(() => addFindingReviewComment(empty, fingerprint, "x".repeat(10_001)), /review comment/);
  assert.throws(() => addFindingReviewComment(empty, fingerprint, "comment\0secret"), /review comment/);
  assert.throws(() => addFindingReviewComment(empty, fingerprint, "comment", { author: "x".repeat(256) }), /author/);
  assert.throws(() => addFindingReviewComment(empty, fingerprint, "comment", { createdAt: "not-a-time" }), /timestamp/);

  assert.equal(isFindingReviewCommentStore({
    schemaVersion: 1,
    comments: {
      [fingerprint]: [{
        id: "id",
        fingerprint,
        body: "comment",
        createdAt: timestamp,
        scannerEvidence: "must not be accepted",
      }],
    },
  }), false);
});

test("review comment persistence is restrictive, atomic-shaped, and corrupt stores fail closed", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-review-comments-"));
  const path = join(root, "state", "comments.json");
  try {
    const store = addFindingReviewComment(emptyFindingReviewCommentStore(), fingerprint, "Triage note only.", {
      author: "maintainer",
      createdAt: timestamp,
    });
    await writeFindingReviewCommentStore(path, store);
    assert.deepEqual(await readFindingReviewCommentStore(path), store);
    assert.equal(JSON.parse(await readFile(path, "utf8")).schemaVersion, 1);
    if (process.platform !== "win32") assert.equal((await stat(path)).mode & 0o777, 0o600);

    await writeFile(path, JSON.stringify({
      schemaVersion: 1,
      comments: {
        [fingerprint]: [{ id: "bad", fingerprint: "different", body: "comment", createdAt: timestamp }],
      },
    }), "utf8");
    await assert.rejects(() => readFindingReviewCommentStore(path), /Not a supported SynSec finding review comment store/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
