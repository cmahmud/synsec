import type { FindingIdentifiers, Severity } from "@synsec/core";
import { runProcess, sanitizeOperationalText } from "@synsec/scanner-sdk";
import type { ScannerAvailability, ScannerProcessRunner } from "@synsec/scanner-sdk";

export type UnknownRecord = Record<string, unknown>;

export function asRecord(value: unknown): UnknownRecord | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as UnknownRecord)
    : undefined;
}

export function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

export function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

export function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export function strings(value: unknown): string[] {
  return asArray(value).filter((item): item is string => typeof item === "string");
}

export function normalizeSeverity(value: unknown): Severity {
  const severity = asString(value)?.trim().toLowerCase();
  if (severity === "critical" || severity === "high" || severity === "medium" || severity === "low" || severity === "info") return severity;
  if (severity === "error") return "high";
  if (severity === "warning" || severity === "warn") return "medium";
  if (severity === "note") return "low";
  return "unknown";
}

export function cvssSeverity(score: number | undefined): Severity {
  if (score === undefined || !Number.isFinite(score)) return "unknown";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

export function identifiersFrom(values: string[]): FindingIdentifiers | undefined {
  const unique = [...new Set(values.map((value) => value.trim()).filter(Boolean))];
  if (unique.length === 0) return undefined;
  const result: FindingIdentifiers = {};
  const cve = unique.filter((value) => /^CVE-/i.test(value));
  const cwe = unique.filter((value) => /^CWE-/i.test(value));
  const ghsa = unique.filter((value) => /^GHSA-/i.test(value));
  const osv = unique.filter((value) => !/^CVE-/i.test(value) && !/^CWE-/i.test(value) && !/^GHSA-/i.test(value));
  if (cve.length) result.cve = cve;
  if (cwe.length) result.cwe = cwe;
  if (ghsa.length) result.ghsa = ghsa;
  if (osv.length) result.osv = osv;
  return result;
}

function normalizedPath(value: string): string {
  return value.replace(/\\/g, "/");
}

function absoluteLike(value: string): boolean {
  return value.startsWith("/") || /^[A-Za-z]:\//.test(value) || value.startsWith("//");
}

export function relativeLike(path: string | undefined, root: string): string | undefined {
  if (!path) return undefined;
  const base = normalizedPath(root).replace(/\/$/, "");
  const candidate = normalizedPath(path).trim();
  if (!candidate) return undefined;
  if (candidate === base) return ".";
  if (candidate.startsWith(`${base}/`)) return candidate.slice(base.length + 1);

  // Scanner output is untrusted. Do not preserve absolute host paths outside
  // the repository or traversal-shaped paths in normalized reports.
  if (absoluteLike(candidate)) return undefined;
  const relative = candidate.replace(/^\.\//, "");
  if (relative === ".." || relative.startsWith("../") || relative.includes("/../")) return undefined;
  return relative;
}

export function safeJson(raw: string): unknown {
  const trimmed = raw.trim();
  return trimmed ? (JSON.parse(trimmed) as unknown) : undefined;
}

export async function commandAvailability(
  command: string,
  args: string[],
  displayName: string,
  runner: ScannerProcessRunner = runProcess,
): Promise<ScannerAvailability> {
  try {
    const output = await runner(command, args, { timeoutMs: 10_000 });
    if (output.exitCode !== 0) {
      return {
        available: false,
        reason: sanitizeOperationalText(output.stderr.trim() || `${displayName} returned a non-zero exit code.`),
      };
    }
    const version = sanitizeOperationalText(output.stdout.trim() || output.stderr.trim());
    return { available: true, version: version || undefined };
  } catch (error) {
    return {
      available: false,
      reason: sanitizeOperationalText(error instanceof Error ? error.message : `${displayName} is not available.`),
    };
  }
}
