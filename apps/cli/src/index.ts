#!/usr/bin/env node

import { stat } from "node:fs/promises";
import { resolve } from "node:path";
import { correlateFindings, type Finding } from "@synsec/core";
import { builtInScanners } from "@synsec/scanners";

const args = process.argv.slice(2);
const command = args[0] ?? "help";

function printHelp(): void {
  console.log(`SynSec v0.1.0

Usage:
  synsec doctor
  synsec scan <path> [--json]

Commands:
  doctor   Show which scanner engines are available.
  scan     Scan a local repository with all available built-in scanners.
`);
}

async function doctor(): Promise<void> {
  console.log("SynSec scanner availability\n");

  for (const scanner of builtInScanners()) {
    const status = await scanner.checkAvailability();
    const marker = status.available ? "OK" : "MISSING";
    const detail = status.version ?? status.reason ?? "";
    console.log(`${marker.padEnd(8)} ${scanner.displayName.padEnd(18)} ${detail}`);
  }
}

function printFinding(finding: Finding): void {
  const location = finding.location
    ? `${finding.location.path}${finding.location.startLine ? `:${finding.location.startLine}` : ""}`
    : "repository";

  console.log(`[${finding.severity.toUpperCase()}] ${finding.title}`);
  console.log(`  ${location}`);
  console.log(`  source: ${finding.scanner.name}${finding.scanner.ruleId ? ` / ${finding.scanner.ruleId}` : ""}`);
  if (finding.remediation) console.log(`  fix: ${finding.remediation}`);
  console.log("");
}

async function scan(): Promise<void> {
  const targetArg = args[1];
  if (!targetArg || targetArg.startsWith("--")) {
    throw new Error("Usage: synsec scan <path> [--json]");
  }

  const targetPath = resolve(targetArg);
  const info = await stat(targetPath).catch(() => undefined);
  if (!info?.isDirectory()) {
    throw new Error(`Scan target is not a directory: ${targetPath}`);
  }

  const scanners = builtInScanners();
  const available = [];

  for (const scanner of scanners) {
    const status = await scanner.checkAvailability();
    if (status.available) {
      available.push(scanner);
    } else if (!args.includes("--json")) {
      console.error(`Skipping ${scanner.displayName}: ${status.reason ?? "not installed"}`);
    }
  }

  if (available.length === 0) {
    throw new Error("No supported scanner engines are available. Run `synsec doctor` for details.");
  }

  const findings: Finding[] = [];
  const scans = [];

  for (const scanner of available) {
    if (!args.includes("--json")) console.error(`Running ${scanner.displayName}...`);
    const result = await scanner.scan({ target: { path: targetPath } });
    scans.push(result);
    findings.push(...result.findings);
  }

  const correlated = correlateFindings(findings);

  if (args.includes("--json")) {
    console.log(
      JSON.stringify(
        {
          target: targetPath,
          scanners: scans.map((result) => result.scanner),
          rawFindingCount: findings.length,
          correlatedFindingCount: correlated.length,
          findings: correlated,
        },
        null,
        2,
      ),
    );
    return;
  }

  console.log(`\n${correlated.length} correlated finding(s) (${findings.length} raw)\n`);
  for (const finding of correlated) printFinding(finding.primary);
}

async function main(): Promise<void> {
  switch (command) {
    case "doctor":
      await doctor();
      break;
    case "scan":
      await scan();
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
  console.error(`SynSec error: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
