#!/usr/bin/env node

import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  assessSynSecScannerIsolationProfile,
  type SynSecScannerIsolationProfile,
} from "@synsec/github/scanner-isolation-profile";

const MAX_PROFILE_BYTES = 64 * 1024;
const args = process.argv.slice(2);

function printHelp(): void {
  console.log(`SynSec scanner isolation profile verifier

Usage:
  synsec-scanner-isolation <profile.json> [--json]

Exit codes:
  0  Every required scanner isolation control is declared.
  2  One or more required controls are missing or unsafe.
  1  The profile or command line is invalid.

This command is offline and credential-free. It validates a declaration of externally enforced
container/sandbox controls; it does not inspect or certify the host runtime.
`);
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

async function readProfile(path: string): Promise<Partial<SynSecScannerIsolationProfile>> {
  const absolute = resolve(path);
  const info = await lstat(absolute).catch(() => undefined);
  if (!info?.isFile() || info.isSymbolicLink()) {
    throw new Error("Scanner isolation profile must be a non-symlink regular file.");
  }
  if (info.size > MAX_PROFILE_BYTES) {
    throw new Error(`Scanner isolation profile exceeds ${MAX_PROFILE_BYTES} bytes.`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(absolute, "utf8"));
  } catch {
    throw new Error("Scanner isolation profile must contain valid JSON.");
  }
  const root = record(parsed);
  if (!root) throw new Error("Scanner isolation profile must contain a JSON object.");

  const allowed = new Set([
    "schemaVersion",
    "runtime",
    "cpuLimit",
    "memoryLimit",
    "networkPolicy",
    "repositoryReadOnly",
    "scratchSeparated",
    "credentialsExcluded",
    "durableStateExcluded",
    "privileged",
    "hostNetwork",
    "hostPid",
    "hostIpc",
    "hostSocketMounts",
  ]);
  for (const key of Object.keys(root)) {
    if (!allowed.has(key)) {
      throw new Error(`Scanner isolation profile contains unsupported field ${key}. Credentials, paths, image registries, and connection details are not accepted.`);
    }
  }

  const profile: Partial<SynSecScannerIsolationProfile> = {};
  if (root.schemaVersion !== undefined) {
    if (root.schemaVersion !== 1) throw new Error("Scanner isolation profile schemaVersion must be 1.");
    profile.schemaVersion = 1;
  }
  if (root.runtime !== undefined) {
    if (root.runtime !== "container" && root.runtime !== "sandbox") {
      throw new Error("Scanner isolation profile runtime must be container or sandbox.");
    }
    profile.runtime = root.runtime;
  }
  if (root.networkPolicy !== undefined) {
    if (root.networkPolicy !== "none" && root.networkPolicy !== "egress-filtered") {
      throw new Error("Scanner isolation profile networkPolicy must be none or egress-filtered.");
    }
    profile.networkPolicy = root.networkPolicy;
  }

  for (const key of [
    "cpuLimit",
    "memoryLimit",
    "repositoryReadOnly",
    "scratchSeparated",
    "credentialsExcluded",
    "durableStateExcluded",
    "privileged",
    "hostNetwork",
    "hostPid",
    "hostIpc",
    "hostSocketMounts",
  ] as const) {
    const value = root[key];
    if (value === undefined) continue;
    if (typeof value !== "boolean") throw new Error(`Scanner isolation profile ${key} must be boolean.`);
    profile[key] = value as never;
  }
  return profile;
}

async function main(): Promise<void> {
  if (args.includes("--help") || args.includes("-h")) {
    printHelp();
    return;
  }
  const unsupported = args.filter((arg, index) => index > 0 && arg !== "--json");
  if (unsupported.length > 0) throw new Error("Unsupported scanner isolation verifier option.");

  const path = args[0];
  if (!path || path.startsWith("--")) {
    printHelp();
    process.exitCode = 1;
    return;
  }

  const assessment = assessSynSecScannerIsolationProfile(await readProfile(path));
  if (args.includes("--json")) {
    console.log(JSON.stringify(assessment, null, 2));
  } else {
    console.log(`Scanner isolation declaration: ${assessment.complete ? "complete" : "incomplete"}`);
    if (assessment.missing.length > 0) {
      console.log("Missing or unsafe controls:");
      for (const control of assessment.missing) console.log(`  - ${control}`);
    } else console.log("Missing or unsafe controls: none");
    console.log(`Interpretation: ${assessment.interpretation}`);
  }
  if (!assessment.complete) process.exitCode = 2;
}

main().catch((error: unknown) => {
  console.error(`SynSec scanner isolation profile error: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
