import { createHash } from "node:crypto";
import { posix } from "node:path";
import type { WorkflowDefinition } from "./index.js";
import { assertWorkflowCapabilitiesAllowed } from "./index.js";

const MAX_CHANGES = 200;
const MAX_PATCH_BYTES = 256 * 1024;
const MAX_TOTAL_PATCH_BYTES = 2 * 1024 * 1024;
const MAX_FINDING_IDS = 500;
const MAX_SUMMARY_LENGTH = 2_000;
const MAX_APPROVER_LENGTH = 200;

export type RemediationChangeOperation = "create" | "modify";

export interface RemediationChangeInput {
  path: string;
  operation: RemediationChangeOperation;
  patch: string;
}

export interface RemediationProposalInput {
  targetCommitSha: string;
  findingIds: readonly string[];
  summary: string;
  changes: readonly RemediationChangeInput[];
}

export interface RemediationChange {
  path: string;
  operation: RemediationChangeOperation;
  patch: string;
  patchSha256: string;
}

export interface RemediationProposal {
  version: 1;
  proposalId: string;
  workflowId: string;
  targetCommitSha: string;
  findingIds: string[];
  summary: string;
  changes: RemediationChange[];
  requiresApproval: true;
  externalNetworkAssessment: "forbidden";
}

export interface RemediationApprovalInput {
  proposalId: string;
  approvedBy: string;
  approvedAt?: string;
}

export interface RemediationApproval {
  version: 1;
  proposalId: string;
  approvedBy: string;
  approvedAt: string;
}

export interface ApprovedRemediationExecution {
  proposal: RemediationProposal;
  approval: RemediationApproval;
  targetCommitSha: string;
}

function commitSha(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (!/^[a-f0-9]{40,64}$/.test(normalized)) {
    throw new Error("Remediation target commit must be a 40-64 character hexadecimal object id.");
  }
  return normalized;
}

function safePath(value: string): string {
  const normalized = value.trim().replaceAll("\\", "/");
  if (!normalized || normalized.startsWith("/") || normalized.includes("\0")) {
    throw new Error("Remediation paths must be non-empty repository-relative paths.");
  }
  const canonical = posix.normalize(normalized);
  if (
    canonical === "." ||
    canonical === ".." ||
    canonical.startsWith("../") ||
    canonical.startsWith(".git/") ||
    canonical === ".git"
  ) {
    throw new Error("Remediation paths must stay inside the repository and may not address .git metadata.");
  }
  if (canonical.length > 512) throw new Error("Remediation path exceeds 512 characters.");
  return canonical;
}

function findingId(value: string): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > 256 || /[\r\n\0]/.test(normalized)) {
    throw new Error("Remediation finding ids must be non-empty single-line identifiers up to 256 characters.");
  }
  return normalized;
}

function boundedPatch(value: string): string {
  if (!value.trim()) throw new Error("Remediation patches must not be empty.");
  const bytes = Buffer.byteLength(value, "utf8");
  if (bytes > MAX_PATCH_BYTES) throw new Error(`Remediation patch exceeds the ${MAX_PATCH_BYTES}-byte per-file limit.`);
  if (value.includes("\0")) throw new Error("Remediation patches may not contain NUL bytes.");
  return value;
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function proposalDigest(input: Omit<RemediationProposal, "proposalId">): string {
  const canonical = JSON.stringify({
    version: input.version,
    workflowId: input.workflowId,
    targetCommitSha: input.targetCommitSha,
    findingIds: input.findingIds,
    summary: input.summary,
    changes: input.changes.map((change) => ({
      path: change.path,
      operation: change.operation,
      patchSha256: change.patchSha256,
    })),
    requiresApproval: true,
    externalNetworkAssessment: "forbidden",
  });
  return digest(canonical);
}

function assertProposalIntegrity(proposal: RemediationProposal): void {
  if (proposal.version !== 1 || proposal.requiresApproval !== true || proposal.externalNetworkAssessment !== "forbidden") {
    throw new Error("Remediation proposal has an invalid safety contract.");
  }
  if (proposal.changes.length === 0 || proposal.changes.length > MAX_CHANGES) {
    throw new Error("Remediation proposal has an invalid change count.");
  }
  let totalPatchBytes = 0;
  const seenPaths = new Set<string>();
  for (const change of proposal.changes) {
    const path = safePath(change.path);
    if (path !== change.path || seenPaths.has(path)) throw new Error("Remediation proposal contains invalid or duplicate paths.");
    seenPaths.add(path);
    if (change.operation !== "create" && change.operation !== "modify") {
      throw new Error("Remediation proposal contains an unsupported change operation.");
    }
    const patch = boundedPatch(change.patch);
    totalPatchBytes += Buffer.byteLength(patch, "utf8");
    if (totalPatchBytes > MAX_TOTAL_PATCH_BYTES) throw new Error("Remediation proposal exceeds the total patch limit.");
    if (digest(patch) !== change.patchSha256) {
      throw new Error("Remediation patch contents no longer match the approved patch hash.");
    }
  }
  if (proposalDigest({
    version: proposal.version,
    workflowId: proposal.workflowId,
    targetCommitSha: commitSha(proposal.targetCommitSha),
    findingIds: proposal.findingIds.map(findingId),
    summary: proposal.summary,
    changes: proposal.changes,
    requiresApproval: true,
    externalNetworkAssessment: "forbidden",
  }) !== proposal.proposalId) {
    throw new Error("Remediation proposal contents no longer match its proposal id.");
  }
}

/**
 * Build an immutable, approval-required remediation proposal for one exact repository commit.
 *
 * The proposal is intentionally a local repository-write artifact: it cannot name an external
 * target, cannot modify .git metadata, cannot delete files, and cannot silently widen beyond the
 * explicitly listed bounded patch set. Approval is not accepted here; proposal creation and write
 * authorization remain separate actions.
 */
export function createRemediationProposal(
  workflow: WorkflowDefinition,
  input: RemediationProposalInput,
): RemediationProposal {
  assertWorkflowCapabilitiesAllowed(workflow, ["propose-remediation"]);
  if (workflow.repositoryWriteRequiresApproval !== true) {
    throw new Error("Remediation workflows must require approval for repository writes.");
  }
  if (workflow.externalNetworkAssessment !== "forbidden") {
    throw new Error("Remediation workflows must forbid external network assessment.");
  }
  if (!Array.isArray(input.changes) || input.changes.length === 0 || input.changes.length > MAX_CHANGES) {
    throw new Error(`Remediation proposals must contain between 1 and ${MAX_CHANGES} file changes.`);
  }
  if (!Array.isArray(input.findingIds) || input.findingIds.length === 0 || input.findingIds.length > MAX_FINDING_IDS) {
    throw new Error(`Remediation proposals must reference between 1 and ${MAX_FINDING_IDS} finding ids.`);
  }
  const summary = input.summary.trim();
  if (!summary || summary.length > MAX_SUMMARY_LENGTH) {
    throw new Error(`Remediation summary must contain between 1 and ${MAX_SUMMARY_LENGTH} characters.`);
  }

  const seenPaths = new Set<string>();
  let totalPatchBytes = 0;
  const changes = input.changes.map((change): RemediationChange => {
    const path = safePath(change.path);
    if (seenPaths.has(path)) throw new Error(`Remediation proposal contains duplicate path: ${path}.`);
    seenPaths.add(path);
    if (change.operation !== "create" && change.operation !== "modify") {
      throw new Error("Remediation changes currently support only create and modify operations.");
    }
    const patch = boundedPatch(change.patch);
    totalPatchBytes += Buffer.byteLength(patch, "utf8");
    if (totalPatchBytes > MAX_TOTAL_PATCH_BYTES) {
      throw new Error(`Remediation proposal exceeds the ${MAX_TOTAL_PATCH_BYTES}-byte total patch limit.`);
    }
    return { path, operation: change.operation, patch, patchSha256: digest(patch) };
  });

  const findingIds = [...new Set(input.findingIds.map(findingId))].sort();
  const partial: Omit<RemediationProposal, "proposalId"> = {
    version: 1,
    workflowId: workflow.id,
    targetCommitSha: commitSha(input.targetCommitSha),
    findingIds,
    summary,
    changes,
    requiresApproval: true,
    externalNetworkAssessment: "forbidden",
  };
  return { ...partial, proposalId: proposalDigest(partial) };
}

export function approveRemediationProposal(
  proposal: RemediationProposal,
  input: RemediationApprovalInput,
): RemediationApproval {
  if (input.proposalId !== proposal.proposalId) {
    throw new Error("Remediation approval does not match the proposed patch set.");
  }
  assertProposalIntegrity(proposal);
  const approvedBy = input.approvedBy.trim();
  if (!approvedBy || approvedBy.length > MAX_APPROVER_LENGTH || /[\r\n\0]/.test(approvedBy)) {
    throw new Error(`Remediation approver must be a single-line identifier up to ${MAX_APPROVER_LENGTH} characters.`);
  }
  const approvedAt = (input.approvedAt ?? new Date().toISOString()).trim();
  if (!Number.isFinite(Date.parse(approvedAt))) throw new Error("Remediation approvedAt must be an ISO timestamp.");
  return { version: 1, proposalId: proposal.proposalId, approvedBy, approvedAt };
}

/**
 * Revalidate approval immediately before a repository writer acts.
 *
 * The caller must supply the repository's current head SHA. A moved head fails closed instead of
 * applying a previously reviewed patch to different source. The returned execution object still
 * performs no write; a GitHub/local writer must consume it explicitly.
 */
export function authorizeRemediationExecution(input: {
  proposal: RemediationProposal;
  approval: RemediationApproval;
  currentHeadSha: string;
}): ApprovedRemediationExecution {
  if (input.approval.version !== 1 || input.approval.proposalId !== input.proposal.proposalId) {
    throw new Error("Remediation approval is for a different proposal.");
  }
  approveRemediationProposal(input.proposal, {
    proposalId: input.approval.proposalId,
    approvedBy: input.approval.approvedBy,
    approvedAt: input.approval.approvedAt,
  });
  const currentHeadSha = commitSha(input.currentHeadSha);
  if (currentHeadSha !== input.proposal.targetCommitSha) {
    throw new Error("Repository head moved after remediation was proposed; regenerate and reapprove the patch set.");
  }
  return {
    proposal: input.proposal,
    approval: input.approval,
    targetCommitSha: currentHeadSha,
  };
}
