import assert from "node:assert/strict";
import test from "node:test";
import {
  approveRemediationProposal,
  authorizeRemediationExecution,
  createRemediationProposal,
} from "@synsec/workflows/remediation";
import { getWorkflow } from "@synsec/workflows";

const workflow = getWorkflow("repository-review");
const head = "a".repeat(40);

function proposal() {
  return createRemediationProposal(workflow, {
    targetCommitSha: head,
    findingIds: ["finding-b", "finding-a"],
    summary: "Harden input handling and add a regression guard.",
    changes: [
      {
        path: "src/handler.ts",
        operation: "modify",
        patch: "@@ -1 +1 @@\n-old\n+new\n",
      },
      {
        path: "tests/handler.test.ts",
        operation: "create",
        patch: "@@ -0,0 +1 @@\n+test('guard', () => {});\n",
      },
    ],
  });
}

test("remediation proposal is exact-commit, bounded, and approval-required", () => {
  const value = proposal();
  assert.equal(value.targetCommitSha, head);
  assert.equal(value.requiresApproval, true);
  assert.equal(value.externalNetworkAssessment, "forbidden");
  assert.deepEqual(value.findingIds, ["finding-a", "finding-b"]);
  assert.match(value.proposalId, /^[a-f0-9]{64}$/);
  assert.equal(value.changes.length, 2);
  assert.match(value.changes[0].patchSha256, /^[a-f0-9]{64}$/);
});

test("approval binds one exact patch set and current repository head", () => {
  const value = proposal();
  const approval = approveRemediationProposal(value, {
    proposalId: value.proposalId,
    approvedBy: "security-reviewer",
    approvedAt: "2026-08-22T20:30:00.000Z",
  });
  const execution = authorizeRemediationExecution({ proposal: value, approval, currentHeadSha: head });
  assert.equal(execution.targetCommitSha, head);
  assert.equal(execution.approval.approvedBy, "security-reviewer");
});

test("remediation rejects path escape, git metadata, duplicates, and deletes", () => {
  const base = {
    targetCommitSha: head,
    findingIds: ["finding-a"],
    summary: "Safe fix",
  };
  assert.throws(() => createRemediationProposal(workflow, {
    ...base,
    changes: [{ path: "../outside", operation: "modify", patch: "x" }],
  }), /stay inside/);
  assert.throws(() => createRemediationProposal(workflow, {
    ...base,
    changes: [{ path: ".git/config", operation: "modify", patch: "x" }],
  }), /may not address .git/);
  assert.throws(() => createRemediationProposal(workflow, {
    ...base,
    changes: [
      { path: "src/a.ts", operation: "modify", patch: "a" },
      { path: "src/./a.ts", operation: "create", patch: "b" },
    ],
  }), /duplicate path/);
  assert.throws(() => createRemediationProposal(workflow, {
    ...base,
    changes: [{ path: "src/a.ts", operation: "delete", patch: "x" }],
  }), /only create and modify/);
});

test("remediation approval fails closed on proposal or patch tampering", () => {
  const value = proposal();
  assert.throws(() => approveRemediationProposal(value, {
    proposalId: "b".repeat(64),
    approvedBy: "reviewer",
  }), /does not match/);

  const tampered = structuredClone(value);
  tampered.changes[0].patch = "@@ -1 +1 @@\n-old\n+attacker-change\n";
  assert.throws(() => approveRemediationProposal(tampered, {
    proposalId: tampered.proposalId,
    approvedBy: "reviewer",
  }), /patch contents no longer match/);
});

test("remediation authorization rejects repository head movement", () => {
  const value = proposal();
  const approval = approveRemediationProposal(value, {
    proposalId: value.proposalId,
    approvedBy: "reviewer",
    approvedAt: "2026-08-22T20:30:00.000Z",
  });
  assert.throws(() => authorizeRemediationExecution({
    proposal: value,
    approval,
    currentHeadSha: "b".repeat(40),
  }), /head moved/);
});

test("workflows without remediation capability cannot create proposals", () => {
  const reportWorkflow = getWorkflow("report-writing");
  assert.throws(() => createRemediationProposal(reportWorkflow, {
    targetCommitSha: head,
    findingIds: ["finding-a"],
    summary: "not allowed",
    changes: [{ path: "src/a.ts", operation: "modify", patch: "x" }],
  }), /does not permit capabilities/);
});
