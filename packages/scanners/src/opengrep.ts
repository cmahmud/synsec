import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import type { Finding, ScanResult } from "@synsec/core";
import type { ScannerAdapter, ScannerAvailability, ScannerContext } from "@synsec/scanner-sdk";
import { runProcess } from "@synsec/scanner-sdk";
import { asArray, asRecord, asString, commandAvailability, identifiersFrom, normalizeSeverity, relativeLike, safeJson, strings } from "./utils.js";

function metadataIdentifiers(metadata: Record<string, unknown> | undefined): string[] {
  if (!metadata) return [];
  const values: string[] = [];
  for (const key of ["cwe", "cve"]) {
    const value = metadata[key];
    if (typeof value === "string") values.push(value);
    else values.push(...strings(value));
  }
  return values.flatMap((value) => value.split(/[,;]\s*/)).map((value) => value.trim()).filter(Boolean);
}

export function parseOpengrepJson(raw: string, root = ""): Finding[] {
  const parsed = asRecord(safeJson(raw));
  if (!parsed) return [];
  const findings: Finding[] = [];
  for (const value of asArray(parsed.results)) {
    const result = asRecord(value);
    if (!result) continue;
    const extra = asRecord(result.extra);
    const start = asRecord(result.start);
    const end = asRecord(result.end);
    const metadata = asRecord(extra?.metadata);
    const ruleId = asString(result.check_id);
    const message = asString(extra?.message) ?? ruleId ?? "Static analysis finding";
    const path = relativeLike(asString(result.path), root);
    const fingerprint = asString(extra?.fingerprint);
    const fix = asString(extra?.fix);
    findings.push({
      id: randomUUID(),
      title: message,
      description: asString(metadata?.description) ?? message,
      category: "sast",
      severity: normalizeSeverity(extra?.severity),
      confidence: 0.9,
      scanner: { name: "opengrep", ruleId },
      location: path ? {
        path,
        startLine: typeof start?.line === "number" ? start.line : undefined,
        endLine: typeof end?.line === "number" ? end.line : undefined,
        startColumn: typeof start?.col === "number" ? start.col : undefined,
        endColumn: typeof end?.col === "number" ? end.col : undefined,
      } : undefined,
      identifiers: identifiersFrom(metadataIdentifiers(metadata)),
      evidence: asString(extra?.lines),
      remediation: fix ?? asString(metadata?.fix),
      fingerprint,
      metadata: {
        technology: metadata?.technology,
        references: metadata?.references,
        owasp: metadata?.owasp,
        likelihood: metadata?.likelihood,
        impact: metadata?.impact,
        confidence: metadata?.confidence,
      },
    });
  }
  return findings;
}

export class OpengrepAdapter implements ScannerAdapter {
  readonly id = "opengrep";
  readonly displayName = "Opengrep";
  readonly capabilities = ["sast"] as const;

  checkAvailability(): Promise<ScannerAvailability> {
    return commandAvailability("opengrep", ["--version"], this.displayName);
  }

  async scan(context: ScannerContext): Promise<ScanResult> {
    const startedAt = new Date().toISOString();
    if (context.changedFiles && context.changedFiles.length === 0) {
      return {
        scanner: this.id,
        startedAt,
        completedAt: new Date().toISOString(),
        target: context.target,
        findings: [],
        diagnostics: ["Changed-file scope is empty; Opengrep was not invoked."],
      };
    }

    const targets = context.changedFiles
      ? context.changedFiles.map((path) => resolve(context.target.path, path))
      : [context.target.path];
    const output = await runProcess(
      "opengrep",
      ["scan", "--json", "--config", "auto", "--metrics", "off", "--taint-intrafile", ...targets],
      { timeoutMs: context.timeoutMs ?? 15 * 60_000, signal: context.signal },
    );
    if (output.exitCode !== 0) throw new Error(`Opengrep scan failed (${output.exitCode}): ${output.stderr.trim()}`);
    return {
      scanner: this.id,
      startedAt,
      completedAt: new Date().toISOString(),
      target: context.target,
      findings: parseOpengrepJson(output.stdout, context.target.path),
      diagnostics: output.stderr.trim() ? [output.stderr.trim()] : [],
    };
  }
}
