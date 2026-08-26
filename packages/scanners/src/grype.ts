import { randomUUID } from "node:crypto";
import type { Finding, ScanResult } from "@synsec/core";
import type {
  ScannerAdapter,
  ScannerAvailability,
  ScannerContext,
  ScannerProcessRunner,
} from "@synsec/scanner-sdk";
import { runProcess } from "@synsec/scanner-sdk";
import { asArray, asRecord, asString, commandAvailability, identifiersFrom, normalizeSeverity, relativeLike, safeJson } from "./utils.js";

export function parseGrypeJson(raw: string, root = ""): Finding[] {
  const parsed = asRecord(safeJson(raw));
  if (!parsed) return [];
  const findings: Finding[] = [];
  for (const value of asArray(parsed.matches)) {
    const match = asRecord(value);
    if (!match) continue;
    const vulnerability = asRecord(match.vulnerability);
    const artifact = asRecord(match.artifact);
    if (!vulnerability || !artifact) continue;
    const vulnId = asString(vulnerability.id) ?? "Known vulnerability";
    const packageName = asString(artifact.name) ?? "unknown package";
    const packageVersion = asString(artifact.version);
    const fix = asRecord(vulnerability.fix);
    const fixedVersions = asArray(fix?.versions).filter((item): item is string => typeof item === "string");
    const aliases = asArray(vulnerability.relatedVulnerabilities)
      .map(asRecord)
      .map((entry) => asString(entry?.id))
      .filter((item): item is string => Boolean(item));
    const firstLocation = asRecord(asArray(artifact.locations)[0]);
    const path = relativeLike(asString(firstLocation?.path), root);
    findings.push({
      id: randomUUID(),
      title: `${vulnId} in ${packageName}`,
      description: asString(vulnerability.description),
      category: "dependency",
      severity: normalizeSeverity(vulnerability.severity),
      confidence: 0.96,
      scanner: { name: "grype", ruleId: vulnId },
      location: path ? { path } : undefined,
      identifiers: identifiersFrom([vulnId, ...aliases]),
      remediation: fixedVersions.length ? `Upgrade ${packageName} to ${fixedVersions[0]} or another listed fixed version.` : undefined,
      metadata: {
        package: packageName,
        version: packageVersion,
        type: asString(artifact.type),
        purl: asString(artifact.purl),
        dataSource: asString(vulnerability.dataSource),
        namespace: asString(vulnerability.namespace),
        fixedVersions,
        fixState: asString(fix?.state),
      },
    });
  }
  return findings;
}

export class GrypeAdapter implements ScannerAdapter {
  readonly id = "grype";
  readonly displayName = "Grype";
  readonly capabilities = ["dependency", "container"] as const;

  constructor(private readonly processRunner: ScannerProcessRunner = runProcess) {}

  checkAvailability(): Promise<ScannerAvailability> {
    return commandAvailability("grype", ["version"], this.displayName, this.processRunner);
  }

  async scan(context: ScannerContext): Promise<ScanResult> {
    const startedAt = new Date().toISOString();
    const output = await this.processRunner(
      "grype",
      [`dir:${context.target.path}`, "-o", "json", "--quiet"],
      { timeoutMs: context.timeoutMs ?? 10 * 60_000, signal: context.signal },
    );
    if (output.exitCode !== 0) throw new Error(`Grype scan failed (${output.exitCode}): ${output.stderr.trim()}`);
    return {
      scanner: this.id,
      startedAt,
      completedAt: new Date().toISOString(),
      target: context.target,
      findings: parseGrypeJson(output.stdout, context.target.path),
      diagnostics: output.stderr.trim() ? [output.stderr.trim()] : [],
    };
  }
}
