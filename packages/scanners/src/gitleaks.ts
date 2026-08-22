import { randomUUID } from "node:crypto";
import { copyFile, lstat, mkdir, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { tmpdir } from "node:os";
import type { Finding, ScanResult } from "@synsec/core";
import type { ScannerAdapter, ScannerAvailability, ScannerContext } from "@synsec/scanner-sdk";
import { runProcess } from "@synsec/scanner-sdk";
import { asArray, asNumber, asRecord, asString, commandAvailability, relativeLike, safeJson } from "./utils.js";

const MAX_CHANGED_FILES = 500;

export function normalizeGitleaksChangedFiles(files: readonly string[] | undefined): string[] | undefined {
  if (files === undefined) return undefined;
  if (files.length === 0) return [];
  if (files.length > MAX_CHANGED_FILES) {
    throw new Error(`Gitleaks changed-file scope exceeds the ${MAX_CHANGED_FILES}-file adapter limit.`);
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
      throw new Error("Gitleaks changed-file scope contains an unsafe repository path.");
    }
    if (!seen.has(path)) {
      seen.add(path);
      result.push(path);
    }
  }
  return result;
}

async function stageChangedFiles(
  repositoryRoot: string,
  stagingRoot: string,
  files: readonly string[],
): Promise<{ staged: true } | { staged: false; reason: string }> {
  await mkdir(stagingRoot, { recursive: true });
  const resolvedRepositoryRoot = resolve(repositoryRoot);
  const resolvedStagingRoot = resolve(stagingRoot);

  for (const path of files) {
    const source = resolve(resolvedRepositoryRoot, path);
    const sourceRelative = relative(resolvedRepositoryRoot, source);
    if (!sourceRelative || sourceRelative === ".." || sourceRelative.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) || isAbsolute(sourceRelative)) {
      return { staged: false, reason: "changed scope escaped the repository root" };
    }

    const info = await lstat(source).catch(() => undefined);
    if (!info?.isFile() || info.isSymbolicLink()) {
      return { staged: false, reason: "changed scope contains a missing, symlink, or non-regular file" };
    }

    const destination = resolve(resolvedStagingRoot, path);
    const destinationRelative = relative(resolvedStagingRoot, destination);
    if (!destinationRelative || destinationRelative === ".." || destinationRelative.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) || isAbsolute(destinationRelative)) {
      return { staged: false, reason: "staged scope escaped the temporary root" };
    }
    await mkdir(dirname(destination), { recursive: true });
    await copyFile(source, destination);
  }

  // Preserve repository-local Gitleaks configuration without exposing unrelated source files.
  const configSource = join(resolvedRepositoryRoot, ".gitleaks.toml");
  const configInfo = await lstat(configSource).catch(() => undefined);
  if (configInfo) {
    if (!configInfo.isFile() || configInfo.isSymbolicLink()) {
      return { staged: false, reason: "repository Gitleaks configuration is not a regular file" };
    }
    const configDestination = join(resolvedStagingRoot, ".gitleaks.toml");
    if (!files.includes(".gitleaks.toml")) await copyFile(configSource, configDestination);
  }

  return { staged: true };
}

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
    const changedFiles = normalizeGitleaksChangedFiles(context.changedFiles);
    if (changedFiles && changedFiles.length === 0) {
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
      let mode: "git" | "dir";
      let target: string;
      let parseRoot = context.target.path;
      const diagnostics: string[] = [];

      if (changedFiles) {
        const stagingRoot = join(temp, "scope");
        const staged = await stageChangedFiles(context.target.path, stagingRoot, changedFiles);
        if (staged.staged) {
          mode = "dir";
          target = stagingRoot;
          parseRoot = stagingRoot;
          diagnostics.push(`Gitleaks scanned ${changedFiles.length} staged changed file(s) with repository-relative paths preserved.`);
        } else {
          const gitRepo = await stat(join(context.target.path, ".git")).then(() => true).catch(() => false);
          mode = gitRepo ? "git" : "dir";
          target = context.target.path;
          diagnostics.push(`Gitleaks changed-file staging was unsafe or ambiguous (${staged.reason}); fell back to a full repository scan.`);
        }
      } else {
        const gitRepo = await stat(join(context.target.path, ".git")).then(() => true).catch(() => false);
        mode = gitRepo ? "git" : "dir";
        target = context.target.path;
      }

      const output = await runProcess(
        "gitleaks",
        [mode, "--report-format", "json", "--report-path", report, "--redact=100", "--no-banner", "--exit-code", "0", target],
        { cwd: context.target.path, timeoutMs: context.timeoutMs ?? 10 * 60_000, signal: context.signal },
      );
      if (output.exitCode !== 0) throw new Error(`Gitleaks scan failed (${output.exitCode}): ${output.stderr.trim()}`);
      const raw = await readFile(report, "utf8").catch(() => "[]");
      if (output.stderr.trim()) diagnostics.push(output.stderr.trim());
      return {
        scanner: this.id,
        startedAt,
        completedAt: new Date().toISOString(),
        target: context.target,
        findings: parseGitleaksJson(raw, parseRoot),
        diagnostics,
      };
    } finally {
      await rm(temp, { recursive: true, force: true });
    }
  }
}
