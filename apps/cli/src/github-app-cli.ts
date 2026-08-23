#!/usr/bin/env node

import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";
import {
  buildSynSecGitHubAppSetupContract,
  buildSynSecGitHubAppSetupRecoveryPlan,
  evaluateSynSecGitHubAppSetup,
  type SynSecGitHubAppSetupOptions,
} from "@synsec/github/app-setup";
import {
  buildSynSecGitHubAppCredentialRotationPlan,
  type SynSecGitHubAppCredentialRotationInput,
} from "@synsec/github/credential-rotation";
import {
  assessGitHubAppSharedStateCapabilities,
  REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES,
  type GitHubAppSharedStateCapabilities,
} from "@synsec/github/app-deployment";

const MAX_SETUP_FILE_BYTES = 256 * 1024;
const args = process.argv.slice(2);
const command = args[0] ?? "help";

function flag(name: string): boolean {
  return args.includes(name);
}

function setupOptions(): SynSecGitHubAppSetupOptions {
  return {
    publishSarif: flag("--sarif"),
    enableRemediationPullRequests: flag("--remediation"),
  };
}

function printHelp(): void {
  console.log(`SynSec GitHub App setup diagnostics

Usage:
  synsec-github-app requirements [--sarif] [--remediation] [--json]
  synsec-github-app evaluate <setup.json> [--sarif] [--remediation] [--json] [--strict]
  synsec-github-app recover <setup.json> [--sarif] [--remediation] [--json] [--strict]
  synsec-github-app rotation <rotation-state.json> [--json]
  synsec-github-app shared-state <capabilities.json> [--json]

Commands:
  requirements  Print the minimum GitHub App permissions and webhook events for enabled features.
  evaluate      Compare an exported/declarative App setup with SynSec's minimum requirements.
  recover       Print deterministic operator actions for missing capability and least-privilege drift.
  rotation      Evaluate secret-free credential rotation acknowledgements before retiring an old credential.
  shared-state  Validate the declared transactional guarantees required for horizontal App replicas.

Feature flags:
  --sarif        Require security_events:write for SARIF/code-scanning publication.
  --remediation  Require contents:write and pull_requests:write for operator-approved remediation PRs.

Output flags:
  --json         Emit machine-readable JSON only.
  --strict       For evaluate/recover, exit 3 when least-privilege drift exists even if required capability is present.

Evaluation/recovery exit codes:
  0  Required capability is present and, unless --strict is used, any extra privilege is advisory only.
  2  Required permissions or webhook events are missing.
  3  --strict was requested and extra write permissions or webhook events were detected.

Rotation exit codes:
  0  Every required rotation acknowledgement is complete; the previous credential can be retired.
  2  One or more required rotation acknowledgements remain incomplete; keep the previous credential active.

Shared-state exit codes:
  0  Every required transactional coordination guarantee is declared.
  2  One or more required guarantees are missing or false; do not horizontally scale the App runtime.

The setup evaluator, recovery planner, rotation planner, and shared-state preflight are offline. They do
not contact GitHub, inspect installation tokens, read repositories, mutate App settings, reload services,
revoke keys, certify databases, or accept credential values. Runtime GitHub authorization, installation-
token permission checks, and real backend concurrency semantics remain authoritative.
`);
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

async function readBoundedJsonObject(path: string, label: string): Promise<Record<string, unknown>> {
  const absolute = resolve(path);
  const info = await stat(absolute).catch(() => undefined);
  if (!info?.isFile()) throw new Error(`${label} file is not a regular file: ${absolute}`);
  if (info.size > MAX_SETUP_FILE_BYTES) throw new Error(`${label} file exceeds ${MAX_SETUP_FILE_BYTES} bytes.`);

  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(absolute, "utf8"));
  } catch {
    throw new Error(`${label} file must contain valid JSON.`);
  }
  const root = record(parsed);
  if (!root) throw new Error(`${label} file must contain a JSON object.`);
  return root;
}

async function readSetupFile(path: string): Promise<{ permissions: Record<string, "read" | "write">; events: string[] }> {
  const root = await readBoundedJsonObject(path, "GitHub App setup");
  const rawPermissions = record(root.permissions);
  if (!rawPermissions) throw new Error("GitHub App setup file must contain a permissions object.");
  if (!Array.isArray(root.events)) throw new Error("GitHub App setup file must contain an events array.");

  const permissions: Record<string, "read" | "write"> = {};
  for (const [name, level] of Object.entries(rawPermissions)) {
    if (level !== "read" && level !== "write") throw new Error(`GitHub App permission ${name} must be read or write.`);
    permissions[name] = level;
  }
  const events = root.events.map((value) => {
    if (typeof value !== "string") throw new Error("GitHub App event names must be strings.");
    return value;
  });
  return { permissions, events };
}

async function readRotationStateFile(path: string): Promise<SynSecGitHubAppCredentialRotationInput> {
  const root = await readBoundedJsonObject(path, "GitHub App rotation state");
  const allowed = new Set([
    "kind",
    "replacementActivated",
    "runtimeReloaded",
    "externalConfigurationUpdated",
    "verificationSucceeded",
  ]);
  for (const key of Object.keys(root)) {
    if (!allowed.has(key)) throw new Error(`GitHub App rotation state contains unsupported field ${key}. Credential values are not accepted.`);
  }
  if (root.kind !== "webhook-secret" && root.kind !== "app-private-key") {
    throw new Error("GitHub App rotation state kind must be webhook-secret or app-private-key.");
  }
  const input: SynSecGitHubAppCredentialRotationInput = { kind: root.kind };
  for (const key of [
    "replacementActivated",
    "runtimeReloaded",
    "externalConfigurationUpdated",
    "verificationSucceeded",
  ] as const) {
    const value = root[key];
    if (value === undefined) continue;
    if (typeof value !== "boolean") throw new Error(`GitHub App rotation state ${key} must be boolean.`);
    input[key] = value;
  }
  return input;
}

async function readSharedStateCapabilitiesFile(path: string): Promise<GitHubAppSharedStateCapabilities> {
  const root = await readBoundedJsonObject(path, "GitHub App shared-state capabilities");
  const allowed = new Set<string>(REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES);
  for (const key of Object.keys(root)) {
    if (!allowed.has(key)) {
      throw new Error(`GitHub App shared-state capabilities contain unsupported field ${key}. Backend credentials and connection details are not accepted.`);
    }
  }

  const capabilities = {} as GitHubAppSharedStateCapabilities;
  for (const capability of REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES) {
    const value = root[capability];
    if (value !== undefined && typeof value !== "boolean") {
      throw new Error(`GitHub App shared-state capability ${capability} must be boolean.`);
    }
    capabilities[capability] = value === true;
  }
  return capabilities;
}

function printRequirements(): void {
  const contract = buildSynSecGitHubAppSetupContract(setupOptions());
  if (flag("--json")) {
    console.log(JSON.stringify(contract, null, 2));
    return;
  }
  console.log("Required permissions:");
  for (const [permission, level] of Object.entries(contract.permissions)) console.log(`  ${permission}: ${level}`);
  console.log("Required webhook events:");
  for (const event of contract.events) console.log(`  ${event}`);
  console.log(`Remediation writes: ${contract.remediationWriteEnabled ? "enabled" : "disabled"}`);
  for (const note of contract.notes) console.log(`Note: ${note}`);
}

function applyEvaluationExitCode(input: { ready: boolean; hasLeastPrivilegeDrift: boolean }): void {
  if (!input.ready) {
    process.exitCode = 2;
    return;
  }
  if (flag("--strict") && input.hasLeastPrivilegeDrift) process.exitCode = 3;
}

async function evaluate(): Promise<void> {
  const path = args[1];
  if (!path || path.startsWith("--")) throw new Error("Usage: synsec-github-app evaluate <setup.json> [--sarif] [--remediation] [--json] [--strict]");
  const setup = await readSetupFile(path);
  const evaluation = evaluateSynSecGitHubAppSetup({ ...setup, options: setupOptions() });
  if (flag("--json")) {
    console.log(JSON.stringify(evaluation, null, 2));
  } else {
    console.log(`Required capability: ${evaluation.ready ? "ready" : "missing"}`);
    if (evaluation.missingPermissions.length > 0) {
      console.log("Missing permissions:");
      for (const item of evaluation.missingPermissions) console.log(`  ${item.permission}: required ${item.required}, actual ${item.actual ?? "absent"}`);
    }
    if (evaluation.missingEvents.length > 0) {
      console.log("Missing webhook events:");
      for (const event of evaluation.missingEvents) console.log(`  ${event}`);
    }
    if (evaluation.excessiveWritePermissions.length > 0) {
      console.log("Least-privilege write drift:");
      for (const permission of evaluation.excessiveWritePermissions) console.log(`  ${permission}: write`);
    }
    if (evaluation.extraEvents.length > 0) {
      console.log("Unused webhook events:");
      for (const event of evaluation.extraEvents) console.log(`  ${event}`);
    }
    console.log(`Interpretation: ${evaluation.interpretation}`);
  }
  applyEvaluationExitCode({
    ready: evaluation.ready,
    hasLeastPrivilegeDrift: evaluation.excessiveWritePermissions.length > 0 || evaluation.extraEvents.length > 0,
  });
}

async function recover(): Promise<void> {
  const path = args[1];
  if (!path || path.startsWith("--")) throw new Error("Usage: synsec-github-app recover <setup.json> [--sarif] [--remediation] [--json] [--strict]");
  const setup = await readSetupFile(path);
  const plan = buildSynSecGitHubAppSetupRecoveryPlan({ ...setup, options: setupOptions() });
  if (flag("--json")) {
    console.log(JSON.stringify(plan, null, 2));
  } else {
    console.log(`Required capability: ${plan.ready ? "ready" : "missing"}`);
    if (plan.requiredActions.length > 0) {
      console.log("Required operator actions:");
      for (const action of plan.requiredActions) console.log(`  - ${action}`);
    } else console.log("Required operator actions: none");
    if (plan.leastPrivilegeReview.length > 0) {
      console.log("Least-privilege review:");
      for (const action of plan.leastPrivilegeReview) console.log(`  - ${action}`);
    } else console.log("Least-privilege review: none");
    console.log(`Interpretation: ${plan.interpretation}`);
  }
  applyEvaluationExitCode({ ready: plan.ready, hasLeastPrivilegeDrift: plan.leastPrivilegeReview.length > 0 });
}

async function rotation(): Promise<void> {
  const path = args[1];
  if (!path || path.startsWith("--")) throw new Error("Usage: synsec-github-app rotation <rotation-state.json> [--json]");
  const plan = buildSynSecGitHubAppCredentialRotationPlan(await readRotationStateFile(path));
  if (flag("--json")) {
    console.log(JSON.stringify(plan, null, 2));
  } else {
    console.log(`Credential: ${plan.kind}`);
    console.log(`Previous credential retirement: ${plan.readyToRetirePrevious ? "ready" : "blocked"}`);
    if (plan.completedSteps.length > 0) {
      console.log("Completed acknowledgements:");
      for (const item of plan.completedSteps) console.log(`  - ${item}`);
    }
    if (plan.requiredActions.length > 0) {
      console.log("Required operator actions:");
      for (const item of plan.requiredActions) console.log(`  - ${item}`);
    }
    console.log(`Interpretation: ${plan.interpretation}`);
  }
  if (!plan.readyToRetirePrevious) process.exitCode = 2;
}

async function sharedState(): Promise<void> {
  const path = args[1];
  if (!path || path.startsWith("--")) throw new Error("Usage: synsec-github-app shared-state <capabilities.json> [--json]");
  const assessment = assessGitHubAppSharedStateCapabilities(await readSharedStateCapabilitiesFile(path));
  if (flag("--json")) {
    console.log(JSON.stringify(assessment, null, 2));
  } else {
    console.log(`Horizontal shared-state contract: ${assessment.complete ? "ready" : "incomplete"}`);
    if (assessment.missing.length > 0) {
      console.log("Missing guarantees:");
      for (const capability of assessment.missing) console.log(`  - ${capability}`);
    } else console.log("Missing guarantees: none");
    console.log("Interpretation: declaration-only-not-backend-certification");
  }
  if (!assessment.complete) process.exitCode = 2;
}

async function main(): Promise<void> {
  switch (command) {
    case "requirements": printRequirements(); break;
    case "evaluate": await evaluate(); break;
    case "recover": await recover(); break;
    case "rotation": await rotation(); break;
    case "shared-state": await sharedState(); break;
    case "help":
    case "--help":
    case "-h": printHelp(); break;
    default:
      printHelp();
      process.exitCode = 1;
  }
}

main().catch((error: unknown) => {
  console.error(`SynSec GitHub App setup error: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
