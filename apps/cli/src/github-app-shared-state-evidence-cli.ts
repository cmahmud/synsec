#!/usr/bin/env node

import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";
import { assessGitHubAppSharedStateConformanceEvidence } from "@synsec/github/shared-state-evidence";

const MAX_EVIDENCE_FILE_BYTES = 1024 * 1024;
const args = process.argv.slice(2);

function flag(name: string): boolean {
  return args.includes(name);
}

function printHelp(): void {
  console.log(`SynSec GitHub App shared-state conformance evidence gate

Usage:
  synsec-github-app-evidence <backend-contract.json> <conformance-report.json> [--json]

Exit codes:
  0  Evidence is structurally valid, complete, and bound to the exact backend implementation.
  2  Evidence is valid JSON but is not sufficient to approve horizontal shared-state readiness.
  1  Input usage, file, size, or JSON parsing failed.

This command is offline and credential-free. It does not connect to a database, contact GitHub,
certify a backend, or accept connection strings. A ready result only means the supplied versioned
backend contract and portable conformance artifact pass SynSec's evidence-binding checks.
`);
}

async function readBoundedJson(path: string, label: string): Promise<unknown> {
  const absolute = resolve(path);
  const info = await stat(absolute).catch(() => undefined);
  if (!info?.isFile()) throw new Error(`${label} is not a regular file: ${absolute}`);
  if (info.size > MAX_EVIDENCE_FILE_BYTES) {
    throw new Error(`${label} exceeds ${MAX_EVIDENCE_FILE_BYTES} bytes.`);
  }

  try {
    return JSON.parse(await readFile(absolute, "utf8"));
  } catch {
    throw new Error(`${label} must contain valid JSON.`);
  }
}

async function main(): Promise<void> {
  if (args.length === 0 || flag("--help") || flag("-h")) {
    printHelp();
    return;
  }

  const contractPath = args[0];
  const reportPath = args[1];
  if (!contractPath || !reportPath || contractPath.startsWith("--") || reportPath.startsWith("--")) {
    throw new Error("Usage: synsec-github-app-evidence <backend-contract.json> <conformance-report.json> [--json]");
  }

  const [contract, report] = await Promise.all([
    readBoundedJson(contractPath, "Shared-state backend contract"),
    readBoundedJson(reportPath, "Shared-state conformance report"),
  ]);
  const assessment = assessGitHubAppSharedStateConformanceEvidence(contract, report);

  if (flag("--json")) {
    console.log(JSON.stringify(assessment, null, 2));
  } else {
    console.log(`Shared-state evidence: ${assessment.ready ? "ready" : "blocked"}`);
    if (assessment.issues.length > 0) {
      console.log("Issues:");
      for (const issue of assessment.issues) console.log(`  - ${issue.code}: ${issue.message}`);
    } else {
      console.log("Issues: none");
    }
    if (assessment.missingScenarioIds.length > 0) {
      console.log("Missing conformance scenarios:");
      for (const id of assessment.missingScenarioIds) console.log(`  - ${id}`);
    }
    console.log("Interpretation: portable-evidence-binding-not-database-certification");
  }

  if (!assessment.ready) process.exitCode = 2;
}

main().catch((error: unknown) => {
  console.error(`SynSec shared-state evidence error: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
