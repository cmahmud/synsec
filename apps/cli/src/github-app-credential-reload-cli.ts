#!/usr/bin/env node

import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  assessSynSecGitHubAppCredentialReload,
  type SynSecGitHubAppCredentialReloadInput,
  type SynSecGitHubAppCredentialReloadReplica,
} from "@synsec/github/credential-reload";

const MAX_INPUT_BYTES = 256 * 1024;
const args = process.argv.slice(2);

function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

async function readInput(path: string): Promise<SynSecGitHubAppCredentialReloadInput> {
  const absolute = resolve(path);
  const info = await lstat(absolute).catch(() => undefined);
  if (!info || info.isSymbolicLink() || !info.isFile()) {
    throw new Error("Credential reload input must be a non-symlink regular file.");
  }
  if (info.size > MAX_INPUT_BYTES) throw new Error(`Credential reload input exceeds ${MAX_INPUT_BYTES} bytes.`);

  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(absolute, "utf8"));
  } catch {
    throw new Error("Credential reload input must contain valid JSON.");
  }

  const root = record(parsed);
  if (!root) throw new Error("Credential reload input must contain a JSON object.");
  const allowed = new Set(["kind", "targetGeneration", "expectedReplicaIds", "replicas"]);
  for (const key of Object.keys(root)) {
    if (!allowed.has(key)) {
      throw new Error(`Credential reload input contains unsupported field ${key}. Credential values are not accepted.`);
    }
  }

  if (root.kind !== "webhook-secret" && root.kind !== "app-private-key") {
    throw new Error("Credential reload kind must be webhook-secret or app-private-key.");
  }
  if (typeof root.targetGeneration !== "string") throw new Error("targetGeneration must be a string identifier.");
  if (!Array.isArray(root.expectedReplicaIds)) throw new Error("expectedReplicaIds must be an array.");
  for (const replicaId of root.expectedReplicaIds) {
    if (typeof replicaId !== "string") throw new Error("Every expectedReplicaId must be a string identifier.");
  }
  if (!Array.isArray(root.replicas)) throw new Error("replicas must be an array.");

  const replicas: SynSecGitHubAppCredentialReloadReplica[] = root.replicas.map((raw) => {
    const replica = record(raw);
    if (!replica) throw new Error("Every replica observation must be an object.");
    const replicaAllowed = new Set(["replicaId", "loadedGeneration", "ready"]);
    for (const key of Object.keys(replica)) {
      if (!replicaAllowed.has(key)) {
        throw new Error(`Replica observation contains unsupported field ${key}. Credential values are not accepted.`);
      }
    }
    if (typeof replica.replicaId !== "string") throw new Error("replicaId must be a string identifier.");
    if (typeof replica.loadedGeneration !== "string") throw new Error("loadedGeneration must be a string identifier.");
    if (typeof replica.ready !== "boolean") throw new Error("replica.ready must be boolean.");
    return {
      replicaId: replica.replicaId,
      loadedGeneration: replica.loadedGeneration,
      ready: replica.ready,
    };
  });

  return {
    kind: root.kind,
    targetGeneration: root.targetGeneration,
    expectedReplicaIds: root.expectedReplicaIds,
    replicas,
  };
}

function printHelp(): void {
  console.log(`SynSec GitHub App credential reload verification

Usage:
  synsec-github-app-reload <reload-state.json> [--json]

Exit codes:
  0  Every specifically expected replica is ready on the exact target configuration generation.
  2  The deployment reload is incomplete, stale, missing required replicas, or contains unexpected observations.
  1  Input or CLI usage is invalid.

The input is credential-free deployment metadata. This command does not read credential values,
contact GitHub, inspect a secret manager, reload services, or revoke credentials.
`);
}

async function main(): Promise<void> {
  if (args.includes("--help") || args.includes("-h")) {
    printHelp();
    return;
  }
  const path = args[0];
  if (!path || path.startsWith("--")) {
    printHelp();
    process.exitCode = 1;
    return;
  }
  const supported = new Set([path, "--json"]);
  for (const arg of args) {
    if (!supported.has(arg)) throw new Error("Unsupported credential reload CLI option.");
  }

  const assessment = assessSynSecGitHubAppCredentialReload(await readInput(path));
  if (args.includes("--json")) {
    console.log(JSON.stringify(assessment, null, 2));
  } else {
    console.log(`Credential: ${assessment.kind}`);
    console.log(`Target generation: ${assessment.targetGeneration}`);
    console.log(`Reload state: ${assessment.complete ? "complete" : "incomplete"}`);
    console.log(`Matched expected replicas: ${assessment.matchedReplicaCount}/${assessment.expectedReplicaCount}`);
    console.log(`Stale expected replicas: ${assessment.staleReplicaCount}`);
    console.log(`Unready expected replicas: ${assessment.unreadyReplicaCount}`);
    console.log(`Missing expected replicas: ${assessment.missingReplicaCount}`);
    console.log(`Unexpected replicas: ${assessment.unexpectedReplicaCount}`);
    console.log(`Interpretation: ${assessment.interpretation}`);
  }
  if (!assessment.complete) process.exitCode = 2;
}

main().catch((error: unknown) => {
  console.error(`SynSec credential reload error: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
