import { randomUUID } from "node:crypto";
import type { Finding, ScanResult, Severity } from "@synsec/core";
import type { ScannerAdapter, ScannerAvailability, ScannerContext } from "@synsec/scanner-sdk";
import { runProcess } from "@synsec/scanner-sdk";
import { asArray, asRecord, asString, commandAvailability, cvssSeverity, identifiersFrom, normalizeSeverity, relativeLike, safeJson, strings } from "./utils.js";

function directSeverity(vuln: Record<string, unknown>): Severity {
  const databaseSpecific = asRecord(vuln.database_specific);
  const direct = normalizeSeverity(databaseSpecific?.severity);
  if (direct !== "unknown") return direct;

  let best = 0;
  for (const value of asArray(vuln.severity)) {
    const entry = asRecord(value);
    const score = asString(entry?.score);
    if (!score) continue;
    const numeric = Number.parseFloat(score);
    if (Number.isFinite(numeric)) best = Math.max(best, numeric);
  }
  return best > 0 ? cvssSeverity(best) : "unknown";
}

function firstFixedVersion(vuln: Record<string, unknown>): string | undefined {
  for (const affectedValue of asArray(vuln.affected)) {
    const affected = asRecord(affectedValue);
    if (!affected) continue;
    for (const rangeValue of asArray(affected.ranges)) {
      const range = asRecord(rangeValue);
      if (!range) continue;
      for (const eventValue of asArray(range.events)) {
        const event = asRecord(eventValue);
        const fixed = asString(event?.fixed);
        if (fixed) return fixed;
      }
    }
  }
  return undefined;
}

export function parseOsvJson(raw: string, root: string): Finding[] {
  const parsed = asRecord(safeJson(raw));
  if (!parsed) return [];
  const findings: Finding[] = [];

  for (const resultValue of asArray(parsed.results)) {
    const result = asRecord(resultValue);
    if (!result) continue;
    const source = asRecord(result.source);
    const sourcePath = relativeLike(asString(source?.path), root);

    for (const packageValue of asArray(result.packages)) {
      const packageResult = asRecord(packageValue);
      if (!packageResult) continue;
      const pkg = asRecord(packageResult.package);
      const name = asString(pkg?.name) ?? "unknown package";
      const version = asString(pkg?.version);
      const ecosystem = asString(pkg?.ecosystem);

      for (const vulnerabilityValue of asArray(packageResult.vulnerabilities)) {
        const vulnerability = asRecord(vulnerabilityValue);
        if (!vulnerability) continue;
        const id = asString(vulnerability.id) ?? "OSV vulnerability";
        const aliases = strings(vulnerability.aliases);
        const fixed = firstFixedVersion(vulnerability);
        const allIds = [id, ...aliases];
        findings.push({
          id: randomUUID(),
          title: `${asString(vulnerability.summary) ?? id} in ${name}`,
          description: asString(vulnerability.details),
          category: "dependency",
          severity: directSeverity(vulnerability),
          confidence: 0.99,
          scanner: { name: "osv-scanner", ruleId: id },
          location: sourcePath ? { path: sourcePath } : undefined,
          identifiers: identifiersFrom(allIds),
          remediation: fixed ? `Upgrade ${name} to ${fixed} or a later non-vulnerable version.` : `Review ${id} and upgrade or replace ${name} when a non-vulnerable version is available.`,
          metadata: {
            package: name,
            version,
            ecosystem,
            fixedVersion: fixed,
            published: asString(vulnerability.published),
            modified: asString(vulnerability.modified),
          },
        });
      }
    }
  }
  return findings;
}

export class OsvScannerAdapter implements ScannerAdapter {
  readonly id = "osv-scanner";
  readonly displayName = "OSV-Scanner";
  readonly capabilities = ["dependency"] as const;

  checkAvailability(): Promise<ScannerAvailability> {
    return commandAvailability("osv-scanner", ["--version"], this.displayName);
  }

  async scan(context: ScannerContext): Promise<ScanResult> {
    const startedAt = new Date().toISOString();
    const output = await runProcess(
      "osv-scanner",
      ["scan", "--format", "json", "source", "-r", context.target.path],
      { timeoutMs: context.timeoutMs ?? 10 * 60_000, signal: context.signal },
    );
    if (output.exitCode !== 0 && output.exitCode !== 1) {
      throw new Error(`OSV-Scanner failed (${output.exitCode}): ${output.stderr.trim()}`);
    }
    return {
      scanner: this.id,
      startedAt,
      completedAt: new Date().toISOString(),
      target: context.target,
      findings: parseOsvJson(output.stdout, context.target.path),
      diagnostics: output.stderr.trim() ? [output.stderr.trim()] : [],
    };
  }
}
