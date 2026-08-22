#!/usr/bin/env node

import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";
import {
  buildSynSecGitHubAppSetupContract,
  buildSynSecGitHubAppSetupRecoveryPlan,
  evaluateSynSecGitHubAppSetup,
  type SynSecGitHubAppSetupOptions,
} from "@synsec/github/app-setup";

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

Commands:
  requirements  Print the minimum GitHub App permissions and webhook events for enabled features.
  evaluate      Compare an exported/declarative App setup with SynSec's minimum requirements.
  recover       Print deterministic operator actions for missing capability and least-privilege drift.

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

The setup evaluator and recovery planner are offline. They do not contact GitHub, inspect
installation tokens, read repositories, mutate App settings, or accept credentials. Runtime GitHub
authorization and installation-token permission checks remain authoritative.
`);
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

async function readSetupFile(path: string): Promise<{ permissions: Record<string, "read" | "write">; events: string[] }> {
  const absolute = resolve(path);
  const info = await stat(absolute).catch(() => undefined);
  if (!info?.isFile()) throw new Error(`GitHub App setup file is not a regular file: ${absolute}`);
  if (info.size > MAX_SETUP_FILE_BYTES) {
    throw new Error(`GitHub App setup file exceeds ${MAX_SETUP_FILE_BYTES} bytes.`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(absolute, "utf8"));
  } catch {
    throw new Error("GitHub App setup file must contain valid JSON.");
  }
  const root = record(parsed);
  if (!root) throw new Error("GitHub App setup file must contain a JSON object.");
  const rawPermissions = record(root.permissions);
  if (!rawPermissions) throw new Error("GitHub App setup file must contain a permissions object.");
  if (!Array.isArray(root.events)) throw new Error("GitHub App setup file must contain an events array.");

  const permissions: Record<string, "read" | "write"> = {};
  for (const [name, level] of Object.entries(rawPermissions)) {
    if (level !== "read" && level !== "write") {
      throw new Error(`GitHub App permission ${name} must be read or write.`);
    }
    permissions[name] = level;
  }
  const events = root.events.map((value) => {
    if (typeof value !== "string") throw new Error("GitHub App event names must be strings.");
    return value;
  });
  return { permissions, events };
}

function printRequirements(): void {
  const contract = buildSynSecGitHubAppSetupContract(setupOptions());
  if (flag("--json")) {
    console.log(JSON.stringify(contract, null, 2));
    return;
  }

  console.log("Required permissions:");
  for (const [permission, level] of Object.entries(contract.permissions)) {
    console.log(`  ${permission}: ${level}`);
  }
  console.log("Required webhook events:");
  for (const event of contract.events) console.log(`  ${event}`);
  console.log(`Remediation writes: ${contract.remediationWriteEnabled ? "enabled" : "disabled"}`);
  for (const note of contract.notes) console.log(`Note: ${note}`);
}

function applyEvaluationExitCode(input: {
  ready: boolean;
  hasLeastPrivilegeDrift: boolean;
}): void {
  if (!input.ready) {
    process.exitCode = 2;
    return;
  }
  if (flag("--strict") && input.hasLeastPrivilegeDrift) process.exitCode = 3;
}

async function evaluate(): Promise<void> {
  const path = args[1];
  if (!path || path.startsWith("--")) {
    throw new Error("Usage: synsec-github-app evaluate <setup.json> [--sarif] [--remediation] [--json] [--strict]");
  }
  const setup = await readSetupFile(path);
  const evaluation = evaluateSynSecGitHubAppSetup({
    ...setup,
    options: setupOptions(),
  });

  if (flag("--json")) {
    console.log(JSON.stringify(evaluation, null, 2));
  } else {
    console.log(`Required capability: ${evaluation.ready ? "ready" : "missing"}`);
    if (evaluation.missingPermissions.length > 0) {
      console.log("Missing permissions:");
      for (const item of evaluation.missingPermissions) {
        console.log(`  ${item.permission}: required ${item.required}, actual ${item.actual ?? "absent"}`);
      }
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
    hasLeastPrivilegeDrift:
      evaluation.excessiveWritePermissions.length > 0 || evaluation.extraEvents.length > 0,
  });
}

async function recover(): Promise<void> {
  const path = args[1];
  if (!path || path.startsWith("--")) {
    throw new Error("Usage: synsec-github-app recover <setup.json> [--sarif] [--remediation] [--json] [--strict]");
  }
  const setup = await readSetupFile(path);
  const plan = buildSynSecGitHubAppSetupRecoveryPlan({
    ...setup,
    options: setupOptions(),
  });

  if (flag("--json")) {
    console.log(JSON.stringify(plan, null, 2));
  } else {
    console.log(`Required capability: ${plan.ready ? "ready" : "missing"}`);
    if (plan.requiredActions.length > 0) {
      console.log("Required operator actions:");
      for (const action of plan.requiredActions) console.log(`  - ${action}`);
    } else {
      console.log("Required operator actions: none");
    }
    if (plan.leastPrivilegeReview.length > 0) {
      console.log("Least-privilege review:");
      for (const action of plan.leastPrivilegeReview) console.log(`  - ${action}`);
    } else {
      console.log("Least-privilege review: none");
    }
    console.log(`Interpretation: ${plan.interpretation}`);
  }

  applyEvaluationExitCode({
    ready: plan.ready,
    hasLeastPrivilegeDrift: plan.leastPrivilegeReview.length > 0,
  });
}

async function main(): Promise<void> {
  switch (command) {
    case "requirements":
      printRequirements();
      break;
    case "evaluate":
      await evaluate();
      break;
    case "recover":
      await recover();
      break;
    case "help":
    case "--help":
    case "-h":
      printHelp();
      break;
    default:
      printHelp();
      process.exitCode = 1;
  }
}

main().catch((error: unknown) => {
  console.error(`SynSec GitHub App setup error: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
