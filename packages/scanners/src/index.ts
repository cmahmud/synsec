import { randomUUID } from "node:crypto";
import type { Finding, ScanResult, Severity } from "@synsec/core";
import type {
  ScannerAdapter,
  ScannerAvailability,
  ScannerContext,
} from "@synsec/scanner-sdk";
import { runProcess } from "@synsec/scanner-sdk";

type UnknownRecord = Record<string, unknown>;

function asRecord(value: unknown): UnknownRecord | undefined {
  return typeof value === "object" && value !== null ? (value as UnknownRecord) : undefined;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function normalizeSeverity(value: unknown): Severity {
  const severity = asString(value)?.toLowerCase();
  if (
    severity === "critical" ||
    severity === "high" ||
    severity === "medium" ||
    severity === "low" ||
    severity === "info"
  ) {
    return severity;
  }
  return "unknown";
}

function trivyLocation(target: string | undefined, line?: number) {
  if (!target) return undefined;
  return line ? { path: target, startLine: line } : { path: target };
}

function parseTrivyVulnerability(item: UnknownRecord, target?: string): Finding {
  const cve = asString(item.VulnerabilityID);
  const title = asString(item.Title) ?? cve ?? "Dependency vulnerability";
  const pkg = asString(item.PkgName);
  const installed = asString(item.InstalledVersion);
  const fixed = asString(item.FixedVersion);

  const remediation = fixed
    ? `Upgrade ${pkg ?? "the affected dependency"} to ${fixed} or later.`
    : undefined;

  return {
    id: randomUUID(),
    title: pkg ? `${title} in ${pkg}` : title,
    description: asString(item.Description),
    category: "dependency",
    severity: normalizeSeverity(item.Severity),
    confidence: 0.95,
    scanner: {
      name: "trivy",
      ruleId: cve,
    },
    location: trivyLocation(target),
    identifiers: cve ? { cve: [cve] } : undefined,
    remediation,
    metadata: {
      package: pkg,
      installedVersion: installed,
      fixedVersion: fixed,
      primaryUrl: asString(item.PrimaryURL),
    },
  };
}

function parseTrivySecret(item: UnknownRecord, target?: string): Finding {
  const ruleId = asString(item.RuleID);
  const startLine = asNumber(item.StartLine);
  return {
    id: randomUUID(),
    title: asString(item.Title) ?? ruleId ?? "Potential secret detected",
    description: asString(item.Category),
    category: "secret",
    severity: normalizeSeverity(item.Severity),
    confidence: 0.9,
    scanner: {
      name: "trivy",
      ruleId,
    },
    location: trivyLocation(target, startLine),
    evidence: asString(item.Match),
    remediation: "Revoke or rotate the exposed credential, then remove it from the repository and history where appropriate.",
  };
}

function parseTrivyMisconfiguration(item: UnknownRecord, target?: string): Finding {
  const ruleId = asString(item.ID) ?? asString(item.AVDID);
  return {
    id: randomUUID(),
    title: asString(item.Title) ?? ruleId ?? "Configuration issue",
    description: asString(item.Description) ?? asString(item.Message),
    category: "misconfiguration",
    severity: normalizeSeverity(item.Severity),
    confidence: 0.9,
    scanner: {
      name: "trivy",
      ruleId,
    },
    location: trivyLocation(target),
    remediation: asString(item.Resolution),
    metadata: {
      namespace: asString(item.Namespace),
      primaryUrl: asString(item.PrimaryURL),
    },
  };
}

function parseTrivyJson(raw: string): Finding[] {
  const parsed = asRecord(JSON.parse(raw));
  if (!parsed) return [];

  const findings: Finding[] = [];

  for (const resultValue of asArray(parsed.Results)) {
    const result = asRecord(resultValue);
    if (!result) continue;
    const target = asString(result.Target);

    for (const value of asArray(result.Vulnerabilities)) {
      const item = asRecord(value);
      if (item) findings.push(parseTrivyVulnerability(item, target));
    }

    for (const value of asArray(result.Secrets)) {
      const item = asRecord(value);
      if (item) findings.push(parseTrivySecret(item, target));
    }

    for (const value of asArray(result.Misconfigurations)) {
      const item = asRecord(value);
      if (item) findings.push(parseTrivyMisconfiguration(item, target));
    }
  }

  return findings;
}

export class TrivyAdapter implements ScannerAdapter {
  readonly id = "trivy";
  readonly displayName = "Trivy";
  readonly capabilities = ["dependency", "secret", "iac", "container"] as const;

  async checkAvailability(): Promise<ScannerAvailability> {
    try {
      const output = await runProcess("trivy", ["--version"], { timeoutMs: 10_000 });
      if (output.exitCode !== 0) {
        return { available: false, reason: output.stderr.trim() || "Trivy returned a non-zero exit code." };
      }
      return { available: true, version: output.stdout.trim() };
    } catch (error) {
      return {
        available: false,
        reason: error instanceof Error ? error.message : "Trivy is not available.",
      };
    }
  }

  async scan(context: ScannerContext): Promise<ScanResult> {
    const startedAt = new Date().toISOString();
    const output = await runProcess(
      "trivy",
      ["fs", "--format", "json", "--scanners", "vuln,secret,misconfig", context.target.path],
      {
        timeoutMs: context.timeoutMs ?? 10 * 60_000,
        signal: context.signal,
      },
    );

    if (output.exitCode !== 0) {
      throw new Error(`Trivy scan failed (${output.exitCode}): ${output.stderr.trim()}`);
    }

    return {
      scanner: this.id,
      startedAt,
      completedAt: new Date().toISOString(),
      target: context.target,
      findings: parseTrivyJson(output.stdout),
      diagnostics: output.stderr.trim() ? [output.stderr.trim()] : [],
    };
  }
}

export function builtInScanners(): ScannerAdapter[] {
  return [new TrivyAdapter()];
}
