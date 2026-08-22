import type { CorrelatedFinding, FindingCategory } from "@synsec/core";

export type WorkflowCapability =
  | "read-normalized-findings"
  | "read-repository-inventory"
  | "read-bounded-source-context"
  | "read-dependency-metadata"
  | "read-redacted-secret-metadata"
  | "read-infrastructure-config"
  | "propose-remediation"
  | "propose-tests";

export interface WorkflowDefinition {
  id: string;
  version: 1;
  displayName: string;
  description: string;
  reviewInstructions: string;
  categories: readonly FindingCategory[] | "all";
  capabilities: readonly WorkflowCapability[];
  sourceContextAllowed: boolean;
  repositoryWriteRequiresApproval: true;
  externalNetworkAssessment: "forbidden";
}

const workflows: readonly WorkflowDefinition[] = [
  {
    id: "repository-review",
    version: 1,
    displayName: "Repository Review",
    description: "Review normalized findings across the repository and explain the strongest evidence first.",
    reviewInstructions: "Prioritize deterministic scanner evidence, actual repository reachability signals, and nearby mitigations. Do not infer an exploitable path merely from a vulnerability class or suspicious API name.",
    categories: "all",
    capabilities: [
      "read-normalized-findings",
      "read-repository-inventory",
      "read-bounded-source-context",
      "propose-remediation",
      "propose-tests",
    ],
    sourceContextAllowed: true,
    repositoryWriteRequiresApproval: true,
    externalNetworkAssessment: "forbidden",
  },
  {
    id: "dependency-review",
    version: 1,
    displayName: "Dependency Review",
    description: "Review known vulnerable dependencies, package identity, fix availability, and available reachability evidence.",
    reviewInstructions: "Distinguish package presence from observed application use. Treat dependencyUsage.status=observed-import as evidence of an import, not proof that a vulnerable function is reachable. Prefer fixed-version guidance already supplied by deterministic scanners.",
    categories: ["dependency", "container", "supply-chain", "license"],
    capabilities: [
      "read-normalized-findings",
      "read-dependency-metadata",
      "read-bounded-source-context",
      "propose-remediation",
      "propose-tests",
    ],
    sourceContextAllowed: true,
    repositoryWriteRequiresApproval: true,
    externalNetworkAssessment: "forbidden",
  },
  {
    id: "secrets-review",
    version: 1,
    displayName: "Secrets Review",
    description: "Review redacted secret findings and recommend rotation/removal without exposing secret values to the model layer.",
    reviewInstructions: "Never request, reconstruct, guess, validate, or reproduce a credential value. Work only from redacted metadata. Recommend proportionate revocation, rotation, history cleanup, and secret-management controls.",
    categories: ["secret"],
    capabilities: [
      "read-normalized-findings",
      "read-redacted-secret-metadata",
      "propose-remediation",
    ],
    sourceContextAllowed: false,
    repositoryWriteRequiresApproval: true,
    externalNetworkAssessment: "forbidden",
  },
  {
    id: "infrastructure-review",
    version: 1,
    displayName: "Infrastructure Review",
    description: "Review IaC, deployment, misconfiguration, and repository-posture findings.",
    reviewInstructions: "Separate policy or posture heuristics from concrete vulnerable configuration. Account for deployment context when present and avoid treating a low Scorecard check as direct exploit evidence.",
    categories: ["iac", "misconfiguration", "repository-posture"],
    capabilities: [
      "read-normalized-findings",
      "read-infrastructure-config",
      "read-bounded-source-context",
      "propose-remediation",
      "propose-tests",
    ],
    sourceContextAllowed: true,
    repositoryWriteRequiresApproval: true,
    externalNetworkAssessment: "forbidden",
  },
] as const;

export function builtInWorkflows(): readonly WorkflowDefinition[] {
  return workflows;
}

export function getWorkflow(id: string): WorkflowDefinition | undefined {
  return workflows.find((workflow) => workflow.id === id);
}

export function workflowFindings(
  findings: readonly CorrelatedFinding[],
  workflow: WorkflowDefinition,
): CorrelatedFinding[] {
  if (workflow.categories === "all") return [...findings];
  const categories = new Set<FindingCategory>(workflow.categories);
  return findings.filter((finding) => categories.has(finding.primary.category));
}

export function assertWorkflowSourceContextAllowed(
  workflow: WorkflowDefinition,
  sourceContextRequested: boolean,
): void {
  if (sourceContextRequested && !workflow.sourceContextAllowed) {
    throw new Error(
      `Workflow ${workflow.id} does not permit source context. This boundary prevents sensitive values from being unnecessarily sent to a model.`,
    );
  }
}
