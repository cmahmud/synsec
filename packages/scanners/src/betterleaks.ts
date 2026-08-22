import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { Finding, ScanResult } from "@synsec/core";
import type { ScannerAdapter, ScannerAvailability, ScannerContext } from "@synsec/scanner-sdk";
import { runProcess } from "@synsec/scanner-sdk";
import { asArray, asNumber, asRecord, asString, commandAvailability, relativeLike, safeJson } from "./utils.js";

export function parseBetterleaksJson(raw: string, root = ""): Finding[] {
  const parsed = safeJson(raw);
  const findings: Finding[] = [];
  for (const value of asArray(parsed)) {
    const item = asRecord(value);
    if (!item) continue;
    const ruleId = asString(item.RuleID);
    const description = asString(item.Description) ?? ruleId ?? "Potential secret detected";
    const attributes = asRecord(item.Attributes);
    const rawFile = asString(item.File) ?? asString(attributes?.path) ?? asString(attributes?.Path);
    const file = relativeLike(rawFile, root);
    const startLine = asNumber(item.StartLine);
    const fingerprint = asString(item.Fingerprint);
    const validationStatus = asString(item.ValidationStatus);

    findings.push({
      id: randomUUID(),
      title: description,
      description: "A credential-like value was detected. SynSec requests fully redacted scanner output and never copies the secret into its normalized finding.",
      category: "secret",
      severity: validationStatus === "valid" ? "critical" : "high",
      confidence: validationStatus === "valid" ? 0.995 : 0.98,
      scanner: { name: "betterleaks", ruleId },
      location: file ? { path: file, startLine } : undefined,
      fingerprint,
      remediation: "Revoke or rotate the credential, remove it from the repository and Git history where necessary, and store credentials outside source control.",
      metadata: {
        validationStatus,
        validationReason: asString(item.ValidationReason),
        commit: asString(item.Commit),
        author: asString(item.Author),
        date: asString(item.Date),
        tags: item.Tags,
      },
    });
  }
  return findings;
}

export class BetterleaksAdapter implements ScannerAdapter {
  readonly id = "betterleaks";
  readonly displayName = "Betterleaks";
  readonly capabilities = ["secret"] as const;

  checkAvailability(): Promise<ScannerAvailability> {
    return commandAvailability("betterleaks", ["version"], this.displayName);
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
        diagnostics: ["Changed-file scope is empty; Betterleaks was not invoked."],
      };
    }

    const temp = await mkdtemp(join(tmpdir(), "synsec-betterleaks-"));
    const report = join(temp, "report.json");
    try {
      const gitRepo = await stat(join(context.target.path, ".git")).then(() => true).catch(() => false);
      const mode = context.changedFiles ? "dir" : gitRepo ? "git" : "dir";
      const targets = context.changedFiles
        ? context.changedFiles.map((path) => resolve(context.target.path, path))
        : [context.target.path];
      const output = await runProcess(
        "betterleaks",
        [
          mode,
          "--report-format", "json",
          "--report-path", report,
          "--redact=100",
          "--no-banner",
          "--exit-code", "0",
          ...targets,
        ],
        { timeoutMs: context.timeoutMs ?? 10 * 60_000, signal: context.signal },
      );
      if (output.exitCode !== 0) throw new Error(`Betterleaks scan failed (${output.exitCode}): ${output.stderr.trim()}`);
      const raw = await readFile(report, "utf8").catch(() => "[]");
      return {
        scanner: this.id,
        startedAt,
        completedAt: new Date().toISOString(),
        target: context.target,
        findings: parseBetterleaksJson(raw, context.target.path),
        diagnostics: output.stderr.trim() ? [output.stderr.trim()] : [],
      };
    } finally {
      await rm(temp, { recursive: true, force: true });
    }
  }
}
