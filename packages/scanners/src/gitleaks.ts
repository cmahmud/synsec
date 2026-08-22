import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { Finding, ScanResult } from "@synsec/core";
import type { ScannerAdapter, ScannerAvailability, ScannerContext } from "@synsec/scanner-sdk";
import { runProcess } from "@synsec/scanner-sdk";
import { asArray, asNumber, asRecord, asString, commandAvailability, relativeLike, safeJson } from "./utils.js";

export function parseGitleaksJson(raw: string, root = ""): Finding[] {
  const parsed = safeJson(raw);
  const findings: Finding[] = [];
  for (const value of asArray(parsed)) {
    const item = asRecord(value);
    if (!item) continue;
    const ruleId = asString(item.RuleID);
    const description = asString(item.Description) ?? ruleId ?? "Potential secret detected";
    const file = relativeLike(asString(item.File), root);
    const startLine = asNumber(item.StartLine);
    const fingerprint = asString(item.Fingerprint);
    findings.push({
      id: randomUUID(),
      title: description,
      description: "A credential-like value was detected. SynSec intentionally omits the secret value from normalized output.",
      category: "secret",
      severity: "high",
      confidence: 0.97,
      scanner: { name: "gitleaks", ruleId },
      location: file ? { path: file, startLine } : undefined,
      fingerprint,
      remediation: "Revoke or rotate the credential, remove it from the repository and Git history where necessary, and use a secret manager or environment variable instead.",
      metadata: {
        entropy: asNumber(item.Entropy),
        commit: asString(item.Commit),
        author: asString(item.Author),
        date: asString(item.Date),
      },
    });
  }
  return findings;
}

export class GitleaksAdapter implements ScannerAdapter {
  readonly id = "gitleaks";
  readonly displayName = "Gitleaks";
  readonly capabilities = ["secret"] as const;

  checkAvailability(): Promise<ScannerAvailability> {
    return commandAvailability("gitleaks", ["version"], this.displayName);
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
        diagnostics: ["Changed-file scope is empty; Gitleaks was not invoked."],
      };
    }

    const temp = await mkdtemp(join(tmpdir(), "synsec-gitleaks-"));
    const report = join(temp, "report.json");
    try {
      const gitRepo = await stat(join(context.target.path, ".git")).then(() => true).catch(() => false);
      const mode = context.changedFiles ? "dir" : gitRepo ? "git" : "dir";
      const targets = context.changedFiles
        ? context.changedFiles.map((path) => resolve(context.target.path, path))
        : [context.target.path];
      const output = await runProcess(
        "gitleaks",
        [mode, "--report-format", "json", "--report-path", report, "--redact=100", "--no-banner", "--exit-code", "0", ...targets],
        { timeoutMs: context.timeoutMs ?? 10 * 60_000, signal: context.signal },
      );
      if (output.exitCode !== 0) throw new Error(`Gitleaks scan failed (${output.exitCode}): ${output.stderr.trim()}`);
      const raw = await readFile(report, "utf8").catch(() => "[]");
      return {
        scanner: this.id,
        startedAt,
        completedAt: new Date().toISOString(),
        target: context.target,
        findings: parseGitleaksJson(raw, context.target.path),
        diagnostics: output.stderr.trim() ? [output.stderr.trim()] : [],
      };
    } finally {
      await rm(temp, { recursive: true, force: true });
    }
  }
}
