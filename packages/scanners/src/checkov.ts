import { randomUUID } from "node:crypto";
import { isAbsolute } from "node:path";
import type { Finding, ScanResult } from "@synsec/core";
import type {
  ScannerAdapter,
  ScannerAvailability,
  ScannerContext,
  ScannerProcessRunner,
} from "@synsec/scanner-sdk";
import { runProcess } from "@synsec/scanner-sdk";
import { asArray, asNumber, asRecord, asString, commandAvailability, normalizeSeverity, relativeLike, safeJson } from "./utils.js";

const MAX_CHANGED_FILES = 500;

function runnerObjects(parsed: unknown): Record<string, unknown>[] {
  if (Array.isArray(parsed)) return parsed.map(asRecord).filter((value): value is Record<string, unknown> => Boolean(value));
  const record = asRecord(parsed);
  return record ? [record] : [];
}

function checkovRepositoryPath(value: unknown): string | undefined {
  const raw = asString(value)?.replace(/^\/+/, "");
  return relativeLike(raw, "");
}

function safeChangedFiles(files: readonly string[] | undefined): string[] | undefined {
  if (files === undefined) return undefined;
  if (files.length === 0) return undefined;
  if (files.length > MAX_CHANGED_FILES) {
    throw new Error(`Checkov changed-file scope exceeds the ${MAX_CHANGED_FILES}-file adapter limit.`);
  }
  const result: string[] = [];
  const seen = new Set<string>();
  for (const value of files) {
    const path = value.replace(/\\/g, "/").replace(/^\.\//, "").trim();
    if (
      !path ||
      isAbsolute(path) ||
      /^[A-Za-z]:\//.test(path) ||
      path === ".." ||
      path.startsWith("../") ||
      path.includes("/../") ||
      path.includes("\0")
    ) {
      throw new Error("Checkov changed-file scope contains an unsafe repository path.");
    }
    if (!seen.has(path)) {
      seen.add(path);
      result.push(path);
    }
  }
  return result.length > 0 ? result : undefined;
}

export function buildCheckovArguments(context: ScannerContext): string[] {
  const files = safeChangedFiles(context.changedFiles);
  if (!files) return ["-d", context.target.path, "-o", "json", "--quiet", "--compact"];
  return [
    "-o",
    "json",
    "--quiet",
    "--compact",
    ...files.flatMap((path) => ["-f", path]),
  ];
}

export function parseCheckovJson(raw: string): Finding[] {
  const parsed = safeJson(raw);
  const findings: Finding[] = [];
  for (const runner of runnerObjects(parsed)) {
    const checkType = asString(runner.check_type);
    const results = asRecord(runner.results);
    for (const value of asArray(results?.failed_checks)) {
      const item = asRecord(value);
      if (!item) continue;
      const ruleId = asString(item.check_id) ?? asString(item.bc_check_id);
      const file = checkovRepositoryPath(item.file_path);
      const range = asArray(item.file_line_range);
      const startLine = asNumber(range[0]);
      const endLine = asNumber(range[1]);
      const guideline = asString(item.guideline);
      findings.push({
        id: randomUUID(),
        title: asString(item.check_name) ?? ruleId ?? "Infrastructure configuration issue",
        description: guideline,
        category: "iac",
        severity: normalizeSeverity(item.severity),
        confidence: 0.92,
        scanner: { name: "checkov", ruleId },
        location: file ? { path: file, startLine, endLine } : undefined,
        remediation: guideline ? `Review the Checkov guidance: ${guideline}` : undefined,
        metadata: {
          framework: checkType,
          resource: asString(item.resource),
          checkClass: asString(item.check_class),
        },
      });
    }
  }
  return findings;
}

export class CheckovAdapter implements ScannerAdapter {
  readonly id = "checkov";
  readonly displayName = "Checkov";
  readonly capabilities = ["iac"] as const;

  constructor(private readonly processRunner: ScannerProcessRunner = runProcess) {}

  checkAvailability(): Promise<ScannerAvailability> {
    return commandAvailability("checkov", ["--version"], this.displayName, this.processRunner);
  }

  async scan(context: ScannerContext): Promise<ScanResult> {
    const startedAt = new Date().toISOString();
    const output = await this.processRunner(
      "checkov",
      buildCheckovArguments(context),
      {
        cwd: context.target.path,
        timeoutMs: context.timeoutMs ?? 10 * 60_000,
        signal: context.signal,
      },
    );
    if (output.exitCode !== 0 && output.exitCode !== 1) {
      throw new Error(`Checkov scan failed (${output.exitCode}): ${output.stderr.trim()}`);
    }
    return {
      scanner: this.id,
      startedAt,
      completedAt: new Date().toISOString(),
      target: context.target,
      findings: parseCheckovJson(output.stdout),
      diagnostics: output.stderr.trim() ? [output.stderr.trim()] : [],
    };
  }
}
