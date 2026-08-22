import { randomUUID } from "node:crypto";
import type { Finding, ScanResult } from "@synsec/core";
import type { ScannerAdapter, ScannerAvailability, ScannerContext } from "@synsec/scanner-sdk";
import { runProcess } from "@synsec/scanner-sdk";
import { asArray, asNumber, asRecord, asString, commandAvailability, normalizeSeverity, relativeLike, safeJson } from "./utils.js";

function location(target: string | undefined, root: string, line?: number) {
  const path = relativeLike(target, root);
  if (!path) return undefined;
  return line ? { path, startLine: line } : { path };
}

function vulnerability(item: Record<string, unknown>, target: string | undefined, root: string): Finding {
  const id = asString(item.VulnerabilityID);
  const pkg = asString(item.PkgName);
  const fixed = asString(item.FixedVersion);
  const title = asString(item.Title) ?? id ?? "Dependency vulnerability";
  return {
    id: randomUUID(),
    title: pkg ? `${title} in ${pkg}` : title,
    description: asString(item.Description),
    category: "dependency",
    severity: normalizeSeverity(item.Severity),
    confidence: 0.95,
    scanner: { name: "trivy", ruleId: id },
    location: location(target, root),
    identifiers: id ? { cve: [id] } : undefined,
    remediation: fixed ? `Upgrade ${pkg ?? "the affected dependency"} to ${fixed} or later.` : undefined,
    metadata: {
      package: pkg,
      installedVersion: asString(item.InstalledVersion),
      fixedVersion: fixed,
      primaryUrl: asString(item.PrimaryURL),
    },
  };
}

function secret(item: Record<string, unknown>, target: string | undefined, root: string): Finding {
  const ruleId = asString(item.RuleID);
  return {
    id: randomUUID(),
    title: asString(item.Title) ?? ruleId ?? "Potential secret detected",
    description: "A credential-like value was detected. SynSec intentionally omits Trivy's matched value from normalized output.",
    category: "secret",
    severity: normalizeSeverity(item.Severity),
    confidence: 0.9,
    scanner: { name: "trivy", ruleId },
    location: location(target, root, asNumber(item.StartLine)),
    remediation: "Revoke or rotate the exposed credential, then remove it from the repository and history where appropriate.",
  };
}

function misconfiguration(item: Record<string, unknown>, target: string | undefined, root: string): Finding {
  const ruleId = asString(item.ID) ?? asString(item.AVDID);
  return {
    id: randomUUID(),
    title: asString(item.Title) ?? ruleId ?? "Configuration issue",
    description: asString(item.Description) ?? asString(item.Message),
    category: "misconfiguration",
    severity: normalizeSeverity(item.Severity),
    confidence: 0.9,
    scanner: { name: "trivy", ruleId },
    location: location(target, root),
    remediation: asString(item.Resolution),
    metadata: { namespace: asString(item.Namespace), primaryUrl: asString(item.PrimaryURL) },
  };
}

export function parseTrivyJson(raw: string, root = ""): Finding[] {
  const parsed = asRecord(safeJson(raw));
  if (!parsed) return [];
  const findings: Finding[] = [];
  for (const value of asArray(parsed.Results)) {
    const result = asRecord(value);
    if (!result) continue;
    const target = asString(result.Target);
    for (const entry of asArray(result.Vulnerabilities)) {
      const item = asRecord(entry);
      if (item) findings.push(vulnerability(item, target, root));
    }
    for (const entry of asArray(result.Secrets)) {
      const item = asRecord(entry);
      if (item) findings.push(secret(item, target, root));
    }
    for (const entry of asArray(result.Misconfigurations)) {
      const item = asRecord(entry);
      if (item) findings.push(misconfiguration(item, target, root));
    }
  }
  return findings;
}

export class TrivyAdapter implements ScannerAdapter {
  readonly id = "trivy";
  readonly displayName = "Trivy";
  readonly capabilities = ["dependency", "secret", "iac", "container"] as const;

  checkAvailability(): Promise<ScannerAvailability> {
    return commandAvailability("trivy", ["--version"], this.displayName);
  }

  async scan(context: ScannerContext): Promise<ScanResult> {
    const startedAt = new Date().toISOString();
    const output = await runProcess("trivy", ["fs", "--format", "json", "--scanners", "vuln,secret,misconfig", context.target.path], {
      timeoutMs: context.timeoutMs ?? 10 * 60_000,
      signal: context.signal,
    });
    if (output.exitCode !== 0) throw new Error(`Trivy scan failed (${output.exitCode}): ${output.stderr.trim()}`);
    return {
      scanner: this.id,
      startedAt,
      completedAt: new Date().toISOString(),
      target: context.target,
      findings: parseTrivyJson(output.stdout, context.target.path),
      diagnostics: output.stderr.trim() ? [output.stderr.trim()] : [],
    };
  }
}
