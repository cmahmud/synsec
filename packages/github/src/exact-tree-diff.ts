import { resolve } from "node:path";
import { runProcess, type ProcessOutput } from "@synsec/scanner-sdk";

const DEFAULT_MAX_TREE_BYTES = 8 * 1024 * 1024;
const DEFAULT_MAX_TREE_ENTRIES = 100_000;
const DEFAULT_MAX_CHANGED_FILES = 5_000;

export type ExactTreeDiffReason =
  | "exact-tree-diff"
  | "tree-read-failed"
  | "invalid-tree-output"
  | "unsupported-tree-change"
  | "deletion-requires-full-scan"
  | "too-many-tree-entries"
  | "too-many-changed-files";

export interface ExactTreeDiffPlan {
  mode: "changed-files" | "full-repository";
  reason: ExactTreeDiffReason;
  changedFiles: string[];
  /** Deleted paths are recorded for diagnostics only; targeted scanners never receive absent paths. */
  deletedFiles: string[];
  interpretation: "exact-commit-tree-comparison-with-conservative-full-scan-fallback";
}

export interface ExactTreeDiffOptions {
  timeoutMs?: number;
  maxTreeBytes?: number;
  maxTreeEntries?: number;
  maxChangedFiles?: number;
  run?: typeof runProcess;
}

interface TreeEntry {
  mode: string;
  type: string;
  object: string;
  path: string;
}

function boundedInteger(value: number | undefined, fallback: number, min: number, max: number, label: string): number {
  const normalized = value ?? fallback;
  if (!Number.isSafeInteger(normalized) || normalized < min || normalized > max) {
    throw new Error(`${label} must be an integer between ${min} and ${max}.`);
  }
  return normalized;
}

function safeRepositoryPath(value: string): string | undefined {
  if (!value || value.includes("\0") || value.includes("\uFFFD")) return undefined;
  const path = value.replaceAll("\\", "/");
  if (path.startsWith("/") || /^[A-Za-z]:\//.test(path)) return undefined;
  const segments = path.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) return undefined;
  return path;
}

function parseTree(output: string, maxEntries: number): Map<string, TreeEntry> | undefined {
  const entries = new Map<string, TreeEntry>();
  const records = output.split("\0");
  if (records.at(-1) === "") records.pop();
  if (records.length > maxEntries) return undefined;

  for (const record of records) {
    const separator = record.indexOf("\t");
    if (separator <= 0) return undefined;
    const metadata = record.slice(0, separator).split(" ");
    if (metadata.length !== 3) return undefined;
    const [mode, type, object] = metadata;
    const path = safeRepositoryPath(record.slice(separator + 1));
    if (!mode || !/^[0-7]{6}$/.test(mode) || !type || !object || !/^[a-f0-9]{40,64}$/i.test(object) || !path) {
      return undefined;
    }
    const key = path.toLowerCase();
    if (entries.has(key)) return undefined;
    entries.set(key, { mode, type, object: object.toLowerCase(), path });
  }
  return entries;
}

async function readTree(
  workspace: string,
  options: { timeoutMs: number; maxTreeBytes: number; maxTreeEntries: number; run: typeof runProcess },
): Promise<Map<string, TreeEntry> | undefined> {
  let result: ProcessOutput;
  try {
    result = await options.run(
      "git",
      ["-C", resolve(workspace), "ls-tree", "-r", "-z", "--full-tree", "HEAD"],
      { timeoutMs: options.timeoutMs, maxOutputBytes: options.maxTreeBytes },
    );
  } catch {
    return undefined;
  }
  if (result.exitCode !== 0 || result.stderr.trim()) return undefined;
  return parseTree(result.stdout, options.maxTreeEntries);
}

function fullPlan(reason: ExactTreeDiffReason, deletedFiles: string[] = []): ExactTreeDiffPlan {
  return {
    mode: "full-repository",
    reason,
    changedFiles: [],
    deletedFiles,
    interpretation: "exact-commit-tree-comparison-with-conservative-full-scan-fallback",
  };
}

/**
 * Compare the exact already-acquired base/head commit trees without fetching history or using branch
 * names. Only changed blob paths that exist in the head may become a targeted scan. Deletions,
 * submodule/tree-type changes, malformed/oversized tree output, or excessive change counts fall back
 * to a full repository scan instead of guessing an incomplete target set.
 */
export async function deriveExactChangedFiles(
  baseWorkspace: string,
  headWorkspace: string,
  options: ExactTreeDiffOptions = {},
): Promise<ExactTreeDiffPlan> {
  const timeoutMs = boundedInteger(options.timeoutMs, 10_000, 1_000, 60_000, "timeoutMs");
  const maxTreeBytes = boundedInteger(options.maxTreeBytes, DEFAULT_MAX_TREE_BYTES, 1_024, 64 * 1024 * 1024, "maxTreeBytes");
  const maxTreeEntries = boundedInteger(options.maxTreeEntries, DEFAULT_MAX_TREE_ENTRIES, 1, 500_000, "maxTreeEntries");
  const maxChangedFiles = boundedInteger(options.maxChangedFiles, DEFAULT_MAX_CHANGED_FILES, 1, 50_000, "maxChangedFiles");
  const run = options.run ?? runProcess;

  const readOptions = { timeoutMs, maxTreeBytes, maxTreeEntries, run };
  const [base, head] = await Promise.all([
    readTree(baseWorkspace, readOptions),
    readTree(headWorkspace, readOptions),
  ]);
  if (!base || !head) return fullPlan("tree-read-failed");
  if (base.size > maxTreeEntries || head.size > maxTreeEntries) return fullPlan("too-many-tree-entries");

  const changedFiles: string[] = [];
  const deletedFiles: string[] = [];
  const allKeys = new Set([...base.keys(), ...head.keys()]);
  for (const key of allKeys) {
    const before = base.get(key);
    const after = head.get(key);
    if (before && after && before.mode === after.mode && before.type === after.type && before.object === after.object) continue;

    if (!after) {
      if (before) deletedFiles.push(before.path);
      continue;
    }
    if (after.type !== "blob" || (before && before.type !== "blob")) {
      return fullPlan("unsupported-tree-change", deletedFiles.sort());
    }
    changedFiles.push(after.path);
    if (changedFiles.length > maxChangedFiles) return fullPlan("too-many-changed-files", deletedFiles.sort());
  }

  deletedFiles.sort();
  if (deletedFiles.length > 0) return fullPlan("deletion-requires-full-scan", deletedFiles);
  changedFiles.sort();
  return {
    mode: "changed-files",
    reason: "exact-tree-diff",
    changedFiles,
    deletedFiles: [],
    interpretation: "exact-commit-tree-comparison-with-conservative-full-scan-fallback",
  };
}
