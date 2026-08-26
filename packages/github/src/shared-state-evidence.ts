import {
  GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS,
  assessGitHubAppSharedStateConformanceCoverage,
} from "./shared-state-conformance.js";
import {
  GITHUB_APP_SHARED_STATE_CONTRACT_VERSION,
  assessGitHubAppSharedStateBackendContract,
  type GitHubAppSharedStateBackendContract,
} from "./shared-state-contract.js";

const REPORT_SCHEMA_VERSION = 1;
const MAX_IDENTIFIER_LENGTH = 128;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const RESULT_STATUSES = new Set(["passed", "failed", "timed-out"]);

export type GitHubAppSharedStateEvidenceIssueCode =
  | "invalid-backend-contract"
  | "invalid-conformance-report"
  | "backend-id-mismatch"
  | "implementation-version-mismatch"
  | "incomplete-conformance";

export interface GitHubAppSharedStateEvidenceIssue {
  code: GitHubAppSharedStateEvidenceIssueCode;
  message: string;
}

export interface GitHubAppSharedStateEvidenceAssessment {
  ready: boolean;
  issues: GitHubAppSharedStateEvidenceIssue[];
  passedScenarioIds: string[];
  missingScenarioIds: string[];
}

interface ParsedConformanceReport {
  backendId: string;
  implementationVersion: string;
  passedScenarioIds: string[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(record: Record<string, unknown>, allowed: readonly string[]): boolean {
  const allowedSet = new Set(allowed);
  const keys = Object.keys(record);
  return keys.length === allowed.length && keys.every((key) => allowedSet.has(key));
}

function validIdentifier(value: unknown): value is string {
  return typeof value === "string"
    && value.length > 0
    && value.length <= MAX_IDENTIFIER_LENGTH
    && IDENTIFIER_PATTERN.test(value);
}

function sameStringArray(value: unknown, expected: readonly string[]): boolean {
  return Array.isArray(value)
    && value.length === expected.length
    && value.every((entry, index) => typeof entry === "string" && entry === expected[index]);
}

function parseConformanceReport(value: unknown): ParsedConformanceReport | undefined {
  if (!isRecord(value) || !exactKeys(value, [
    "schemaVersion",
    "backendId",
    "implementationVersion",
    "complete",
    "scenarioTimeoutMs",
    "results",
    "coverage",
  ])) return undefined;
  if (value.schemaVersion !== REPORT_SCHEMA_VERSION) return undefined;
  if (!validIdentifier(value.backendId) || !validIdentifier(value.implementationVersion)) return undefined;
  if (typeof value.complete !== "boolean") return undefined;
  if (!Number.isSafeInteger(value.scenarioTimeoutMs) || (value.scenarioTimeoutMs as number) < 100 || (value.scenarioTimeoutMs as number) > 120_000) {
    return undefined;
  }
  if (!Array.isArray(value.results) || value.results.length !== GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.length) {
    return undefined;
  }

  const requiredIds = GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.map((scenario) => scenario.id);
  const requiredIdSet = new Set<string>(requiredIds);
  const seen = new Set<string>();
  const passedScenarioIds: string[] = [];
  for (const result of value.results) {
    if (!isRecord(result) || !exactKeys(result, ["id", "status", "durationMs"])) return undefined;
    if (typeof result.id !== "string" || !requiredIdSet.has(result.id) || seen.has(result.id)) return undefined;
    if (typeof result.status !== "string" || !RESULT_STATUSES.has(result.status)) return undefined;
    if (!Number.isSafeInteger(result.durationMs) || (result.durationMs as number) < 0) return undefined;
    seen.add(result.id);
    if (result.status === "passed") passedScenarioIds.push(result.id);
  }
  if (requiredIds.some((id) => !seen.has(id))) return undefined;

  const coverage = assessGitHubAppSharedStateConformanceCoverage(passedScenarioIds);
  if (value.complete !== coverage.complete) return undefined;
  if (!isRecord(value.coverage) || !exactKeys(value.coverage, [
    "complete",
    "coveredScenarioIds",
    "missingScenarioIds",
    "missingCapabilities",
  ])) return undefined;
  if (value.coverage.complete !== coverage.complete) return undefined;
  if (!sameStringArray(value.coverage.coveredScenarioIds, coverage.coveredScenarioIds)) return undefined;
  if (!sameStringArray(value.coverage.missingScenarioIds, coverage.missingScenarioIds)) return undefined;
  if (!sameStringArray(value.coverage.missingCapabilities, coverage.missingCapabilities)) return undefined;

  return {
    backendId: value.backendId,
    implementationVersion: value.implementationVersion,
    passedScenarioIds: coverage.coveredScenarioIds,
  };
}

/**
 * Validate that a portable conformance artifact is structurally sound, complete, and bound to the
 * same concrete adapter revision as a valid versioned backend contract.
 *
 * This gate intentionally ignores backend-provided error text and does not certify a database. It is
 * suitable for deployment/provisioning policy that must reject detached, stale, or tampered evidence.
 */
export function assessGitHubAppSharedStateConformanceEvidence(
  backendContract: unknown,
  conformanceReport: unknown,
): GitHubAppSharedStateEvidenceAssessment {
  const issues: GitHubAppSharedStateEvidenceIssue[] = [];
  const contractAssessment = assessGitHubAppSharedStateBackendContract(backendContract);
  if (!contractAssessment.ready) {
    issues.push({
      code: "invalid-backend-contract",
      message: "Shared-state backend contract is not ready for conformance evidence binding.",
    });
  }

  const report = parseConformanceReport(conformanceReport);
  if (!report) {
    issues.push({
      code: "invalid-conformance-report",
      message: "Shared-state conformance report has an invalid, incomplete, or unsupported shape.",
    });
    return {
      ready: false,
      issues,
      passedScenarioIds: [],
      missingScenarioIds: GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.map((scenario) => scenario.id),
    };
  }

  const coverage = assessGitHubAppSharedStateConformanceCoverage(report.passedScenarioIds);
  if (!coverage.complete) {
    issues.push({
      code: "incomplete-conformance",
      message: "Shared-state conformance report does not pass every required adversarial scenario.",
    });
  }

  if (contractAssessment.ready) {
    const contract = backendContract as GitHubAppSharedStateBackendContract;
    if (contract.contractVersion !== GITHUB_APP_SHARED_STATE_CONTRACT_VERSION) {
      issues.push({
        code: "invalid-backend-contract",
        message: "Shared-state backend contract version is unsupported.",
      });
    } else {
      if (contract.backendId !== report.backendId) {
        issues.push({
          code: "backend-id-mismatch",
          message: "Shared-state conformance report is bound to a different backend id.",
        });
      }
      if (contract.implementationVersion !== report.implementationVersion) {
        issues.push({
          code: "implementation-version-mismatch",
          message: "Shared-state conformance report is bound to a different implementation version.",
        });
      }
    }
  }

  return {
    ready: issues.length === 0,
    issues,
    passedScenarioIds: coverage.coveredScenarioIds,
    missingScenarioIds: coverage.missingScenarioIds,
  };
}
