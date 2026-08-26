import {
  REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES,
  type GitHubAppSharedStateCapabilities,
  type GitHubAppSharedStateCapability,
} from "./app-deployment.js";

export const GITHUB_APP_SHARED_STATE_CONTRACT_VERSION = 1 as const;

export type GitHubAppSharedStateEvidenceMechanism =
  | "database-constraint"
  | "serializable-transaction"
  | "compare-and-set"
  | "fencing-token"
  | "shared-durable-store";

export interface GitHubAppSharedStateCapabilityEvidence {
  capability: GitHubAppSharedStateCapability;
  mechanism: GitHubAppSharedStateEvidenceMechanism;
  /** Stable implementation/test reference; never a connection string or credential. */
  reference: string;
}

export interface GitHubAppSharedStateBackendContract {
  contractVersion: typeof GITHUB_APP_SHARED_STATE_CONTRACT_VERSION;
  /** Stable non-secret adapter identity, for example `postgres-v1`. */
  backendId: string;
  /** Adapter/build version used to produce the declaration. */
  implementationVersion: string;
  capabilities: GitHubAppSharedStateCapabilities;
  evidence: GitHubAppSharedStateCapabilityEvidence[];
}

export type GitHubAppSharedStateContractIssueCode =
  | "invalid-shape"
  | "unsupported-contract-version"
  | "invalid-backend-id"
  | "invalid-implementation-version"
  | "invalid-capabilities"
  | "invalid-evidence"
  | "duplicate-evidence"
  | "missing-capability-evidence";

export interface GitHubAppSharedStateContractIssue {
  code: GitHubAppSharedStateContractIssueCode;
  capability?: GitHubAppSharedStateCapability;
  message: string;
}

export interface GitHubAppSharedStateContractAssessment {
  ready: boolean;
  issues: GitHubAppSharedStateContractIssue[];
  missingEvidence: GitHubAppSharedStateCapability[];
}

const MAX_IDENTIFIER_LENGTH = 128;
const MAX_REFERENCE_LENGTH = 240;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const EVIDENCE_MECHANISMS = new Set<GitHubAppSharedStateEvidenceMechanism>([
  "database-constraint",
  "serializable-transaction",
  "compare-and-set",
  "fencing-token",
  "shared-durable-store",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(record: Record<string, unknown>, allowed: readonly string[]): boolean {
  const allowedSet = new Set(allowed);
  return Object.keys(record).every((key) => allowedSet.has(key));
}

function validIdentifier(value: unknown): value is string {
  return typeof value === "string" && value.length <= MAX_IDENTIFIER_LENGTH && IDENTIFIER_PATTERN.test(value);
}

function validReference(value: unknown): value is string {
  return typeof value === "string"
    && value.length > 0
    && value.length <= MAX_REFERENCE_LENGTH
    && !/[\u0000-\u001f\u007f]/.test(value)
    && !/:\/\//.test(value)
    && !/@/.test(value);
}

function parseCapabilities(value: unknown): GitHubAppSharedStateCapabilities | undefined {
  if (!isRecord(value) || !exactKeys(value, REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES)) return undefined;
  for (const capability of REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES) {
    if (value[capability] !== true) return undefined;
  }
  return value as unknown as GitHubAppSharedStateCapabilities;
}

/**
 * Validate a secret-free declaration describing one concrete shared-state adapter build.
 *
 * This does not certify the backend or execute concurrency tests. It makes the integration
 * boundary versioned, attributable, complete, and suitable for binding to independent
 * conformance-test evidence without accepting connection details or arbitrary URLs.
 */
export function assessGitHubAppSharedStateBackendContract(
  value: unknown,
): GitHubAppSharedStateContractAssessment {
  const issues: GitHubAppSharedStateContractIssue[] = [];
  const missingEvidence: GitHubAppSharedStateCapability[] = [];

  if (!isRecord(value) || !exactKeys(value, ["contractVersion", "backendId", "implementationVersion", "capabilities", "evidence"])) {
    return {
      ready: false,
      issues: [{ code: "invalid-shape", message: "Shared-state backend contract has an invalid or unsupported shape." }],
      missingEvidence: [...REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES],
    };
  }

  if (value.contractVersion !== GITHUB_APP_SHARED_STATE_CONTRACT_VERSION) {
    issues.push({
      code: "unsupported-contract-version",
      message: `Shared-state backend contract version must be ${GITHUB_APP_SHARED_STATE_CONTRACT_VERSION}.`,
    });
  }
  if (!validIdentifier(value.backendId)) {
    issues.push({ code: "invalid-backend-id", message: "Shared-state backend id must be a bounded non-secret identifier." });
  }
  if (!validIdentifier(value.implementationVersion)) {
    issues.push({
      code: "invalid-implementation-version",
      message: "Shared-state implementation version must be a bounded non-secret identifier.",
    });
  }

  const capabilities = parseCapabilities(value.capabilities);
  if (!capabilities) {
    issues.push({
      code: "invalid-capabilities",
      message: "Shared-state backend contract must explicitly declare every required capability as true.",
    });
  }

  const evidenced = new Set<GitHubAppSharedStateCapability>();
  if (!Array.isArray(value.evidence) || value.evidence.length > REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES.length) {
    issues.push({ code: "invalid-evidence", message: "Shared-state capability evidence must contain at most one entry per required capability." });
  } else {
    for (const entry of value.evidence) {
      if (!isRecord(entry) || !exactKeys(entry, ["capability", "mechanism", "reference"])) {
        issues.push({ code: "invalid-evidence", message: "Shared-state capability evidence contains an invalid entry." });
        continue;
      }
      const capability = typeof entry.capability === "string"
        && REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES.includes(entry.capability as GitHubAppSharedStateCapability)
        ? entry.capability as GitHubAppSharedStateCapability
        : undefined;
      if (!capability || typeof entry.mechanism !== "string"
        || !EVIDENCE_MECHANISMS.has(entry.mechanism as GitHubAppSharedStateEvidenceMechanism)
        || !validReference(entry.reference)) {
        issues.push({ code: "invalid-evidence", message: "Shared-state capability evidence contains unsupported or unsafe values." });
        continue;
      }
      if (evidenced.has(capability)) {
        issues.push({ code: "duplicate-evidence", capability, message: `Shared-state capability ${capability} has duplicate evidence.` });
        continue;
      }
      evidenced.add(capability);
    }
  }

  for (const capability of REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES) {
    if (!evidenced.has(capability)) {
      missingEvidence.push(capability);
      issues.push({
        code: "missing-capability-evidence",
        capability,
        message: `Shared-state capability ${capability} is missing implementation evidence.`,
      });
    }
  }

  return { ready: issues.length === 0 && Boolean(capabilities), issues, missingEvidence };
}

export function assertGitHubAppSharedStateBackendContract(value: unknown): asserts value is GitHubAppSharedStateBackendContract {
  const assessment = assessGitHubAppSharedStateBackendContract(value);
  if (assessment.ready) return;
  throw new Error(`GitHub App shared-state backend contract is not ready: ${assessment.issues.map((issue) => issue.code).join(", ")}`);
}
