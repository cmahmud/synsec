import { readFile } from "node:fs/promises";
import type { FindingCategory } from "@synsec/core";
import type { WorkflowCapability, WorkflowDefinition } from "./index.js";

const capabilities = new Set<WorkflowCapability>([
  "read-normalized-findings",
  "read-repository-inventory",
  "read-bounded-source-context",
  "read-dependency-metadata",
  "read-redacted-secret-metadata",
  "read-infrastructure-config",
  "read-scan-reports",
  "read-lifecycle-state",
  "propose-remediation",
  "propose-tests",
]);

const categories = new Set<FindingCategory>([
  "sast",
  "dependency",
  "secret",
  "misconfiguration",
  "iac",
  "container",
  "supply-chain",
  "repository-posture",
  "license",
  "other",
]);

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Workflow definition must be a JSON object.");
  }
  return value as Record<string, unknown>;
}

function requiredString(input: Record<string, unknown>, key: string, maxLength: number): string {
  const value = input[key];
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`Workflow field ${key} must be a non-empty string.`);
  }
  if (value.length > maxLength) throw new Error(`Workflow field ${key} exceeds ${maxLength} characters.`);
  return value;
}

function parseCategories(value: unknown): readonly FindingCategory[] | "all" {
  if (value === "all") return "all";
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error("Workflow categories must be \"all\" or a non-empty array.");
  }
  const parsed = [...new Set(value.map((item) => {
    if (typeof item !== "string" || !categories.has(item as FindingCategory)) {
      throw new Error(`Unsupported workflow category: ${String(item)}.`);
    }
    return item as FindingCategory;
  }))];
  return parsed;
}

function parseCapabilities(value: unknown): readonly WorkflowCapability[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error("Workflow capabilities must be a non-empty array.");
  }
  return [...new Set(value.map((item) => {
    if (typeof item !== "string" || !capabilities.has(item as WorkflowCapability)) {
      throw new Error(`Unsupported workflow capability: ${String(item)}.`);
    }
    return item as WorkflowCapability;
  }))];
}

export function parseUserWorkflow(value: unknown): WorkflowDefinition {
  const input = record(value);
  if (input.version !== 1) throw new Error("User-defined workflows must declare version 1.");

  const id = requiredString(input, "id", 80);
  if (!/^[a-z0-9][a-z0-9-]*$/.test(id)) {
    throw new Error("Workflow id must contain only lowercase letters, numbers, and hyphens.");
  }
  const displayName = requiredString(input, "displayName", 120);
  const description = requiredString(input, "description", 1_000);
  const reviewInstructions = requiredString(input, "reviewInstructions", 8_000);
  const parsedCapabilities = parseCapabilities(input.capabilities);
  const parsedCategories = parseCategories(input.categories);

  if (typeof input.sourceContextAllowed !== "boolean") {
    throw new Error("Workflow sourceContextAllowed must be a boolean.");
  }
  if (input.sourceContextAllowed && !parsedCapabilities.includes("read-bounded-source-context")) {
    throw new Error("A workflow may allow source context only when read-bounded-source-context is declared.");
  }
  if (input.repositoryWriteRequiresApproval !== true) {
    throw new Error("User-defined workflows must require approval for repository writes.");
  }
  if (input.externalNetworkAssessment !== "forbidden") {
    throw new Error("User-defined repository workflows must forbid external network assessment.");
  }

  return {
    id,
    version: 1,
    displayName,
    description,
    reviewInstructions,
    categories: parsedCategories,
    capabilities: parsedCapabilities,
    sourceContextAllowed: input.sourceContextAllowed,
    repositoryWriteRequiresApproval: true,
    externalNetworkAssessment: "forbidden",
  };
}

export async function readUserWorkflow(path: string): Promise<WorkflowDefinition> {
  const source = await readFile(path, "utf8");
  if (source.length > 64_000) throw new Error("Workflow definition exceeds the 64 KiB size limit.");
  let parsed: unknown;
  try {
    parsed = JSON.parse(source) as unknown;
  } catch (error) {
    throw new Error(`Workflow definition is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  return parseUserWorkflow(parsed);
}
