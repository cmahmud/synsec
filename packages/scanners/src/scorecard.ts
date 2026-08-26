import { randomUUID } from "node:crypto";
import type { Finding, ScanResult, Severity } from "@synsec/core";
import type { ScannerAdapter, ScannerAvailability, ScannerContext } from "@synsec/scanner-sdk";
import { runProcess } from "@synsec/scanner-sdk";
import { asArray, asNumber, asRecord, asString, commandAvailability, safeJson } from "./utils.js";

function severityForScore(score: number | undefined): Severity {
  if (score === undefined || score < 0) return "unknown";
  if (score <= 3) return "high";
  if (score <= 6) return "medium";
  if (score <= 8) return "low";
  return "info";
}

function confidenceForScore(score: number | undefined): number {
  if (score === undefined || score < 0) return 0.6;
  return 0.9;
}

export function parseScorecardJson(raw: string): Finding[] {
  const parsed = asRecord(safeJson(raw));
  if (!parsed) return [];

  const findings: Finding[] = [];
  for (const value of asArray(parsed.checks)) {
    const check = asRecord(value);
    if (!check) continue;
    const name = asString(check.name) ?? "Repository posture check";
    const score = asNumber(check.score);

    // A perfect check is evidence of good posture rather than a vulnerability.
    // Preserve aggregate/report metadata elsewhere instead of manufacturing a finding.
    if (score === 10) continue;

    const documentation = asRecord(check.documentation);
    const reason = asString(check.reason);
    const details = asArray(check.details).filter((item): item is string => typeof item === "string");
    const shortDoc = asString(documentation?.short);
    const docUrl = asString(documentation?.url);

    findings.push({
      id: randomUUID(),
      title: `${name} repository posture check scored ${score ?? "unknown"}/10`,
      description: reason ?? shortDoc ?? `OpenSSF Scorecard reported a non-perfect result for ${name}.`,
      category: "repository-posture",
      severity: severityForScore(score),
      confidence: confidenceForScore(score),
      scanner: { name: "scorecard", ruleId: name },
      remediation: shortDoc,
      metadata: {
        score,
        reason,
        details,
        documentation: docUrl,
      },
    });
  }
  return findings;
}

export class ScorecardAdapter implements ScannerAdapter {
  readonly id = "scorecard";
  readonly displayName = "OpenSSF Scorecard";
  readonly capabilities = ["repository-posture"] as const;

  checkAvailability(): Promise<ScannerAvailability> {
    return commandAvailability("scorecard", ["--version"], this.displayName);
  }

  async scan(context: ScannerContext): Promise<ScanResult> {
    const startedAt = new Date().toISOString();
    const output = await runProcess(
      "scorecard",
      [
        `--local=${context.target.path}`,
        "--format=json",
        "--show-details",
      ],
      { timeoutMs: context.timeoutMs ?? 15 * 60_000, signal: context.signal },
    );

    if (output.exitCode !== 0) {
      throw new Error(`OpenSSF Scorecard scan failed (${output.exitCode}): ${output.stderr.trim()}`);
    }

    return {
      scanner: this.id,
      startedAt,
      completedAt: new Date().toISOString(),
      target: context.target,
      findings: parseScorecardJson(output.stdout),
      diagnostics: output.stderr.trim() ? [output.stderr.trim()] : [],
    };
  }
}
