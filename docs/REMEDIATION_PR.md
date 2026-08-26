# Remediation PR workflow

SynSec remediation remains repository-first and approval-gated. The `remediation-pr` workflow may prepare a patch proposal from normalized repository findings and bounded source context, but proposal generation is not permission to write a branch, commit, or pull request.

`@synsec/workflows/remediation` defines the artifact boundary used between review and any future repository writer.

## Proposal contract

A remediation proposal is bound to one exact repository commit SHA and one explicit set of finding ids. It contains between 1 and 200 repository-relative file changes and currently permits only `create` and `modify` operations. File deletion is intentionally unsupported in this first write workflow because it is higher impact and harder to review safely.

Each patch is bounded to 256 KiB and the whole proposal to 2 MiB of patch text. Paths are normalized and cannot escape the repository or address `.git` metadata. Duplicate normalized paths are rejected. External network assessment remains forbidden by the workflow policy.

The proposal id is a SHA-256 digest over the workflow id, target commit, finding ids, summary, file paths, operations, and per-patch hashes. Before approval or execution, SynSec re-hashes every patch body and revalidates the full proposal digest. Changing patch text after review therefore invalidates the proposal even if the stored patch hash is left untouched.

## Explicit approval

`approveRemediationProposal()` requires the exact proposal id and records a bounded approver identifier plus approval timestamp. It does not perform a repository write.

Immediately before a writer acts, `authorizeRemediationExecution()` revalidates both the proposal and approval and requires the repository's current head SHA to still equal the proposal target SHA. If the head moved, execution fails closed and the patch must be regenerated and reapproved against the new source state.

```ts
import { getWorkflow } from "@synsec/workflows";
import {
  approveRemediationProposal,
  authorizeRemediationExecution,
  createRemediationProposal,
} from "@synsec/workflows/remediation";

const workflow = getWorkflow("remediation-pr");
if (!workflow) throw new Error("remediation-pr workflow unavailable");

const proposal = createRemediationProposal(workflow, {
  targetCommitSha: scan.report.target.commitSha,
  findingIds: [finding.fingerprint],
  summary: "Validate the affected input and add a regression test.",
  changes: proposedChanges,
});

// Present the exact proposal/patch set to a human review surface first.
const approval = approveRemediationProposal(proposal, {
  proposalId: proposal.proposalId,
  approvedBy: reviewerIdentity,
});

const execution = authorizeRemediationExecution({
  proposal,
  approval,
  currentHeadSha,
});
```

## Writer boundary

The execution object is still only authorization evidence. This module deliberately does not create branches, commits, or pull requests and does not hold GitHub write credentials. A repository writer must consume the approved object explicitly and preserve the same exact-head and exact-patch boundaries.

When GitHub write execution is added, it should use a purpose-specific installation token with the minimum repository permission needed, create a dedicated SynSec remediation branch, refuse force-pushes, never modify an unrelated branch, and publish the proposal id and source commit in the pull-request metadata. Any change to the approved patch set must require a new proposal id and a new approval.

This workflow does not permit live-target exploitation, secret retrieval or validation, persistence, arbitrary repository expansion, or autonomous merging.
