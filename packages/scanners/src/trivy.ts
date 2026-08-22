import { randomUUID } from "node:crypto";
import { copyFile, lstat, mkdir, mkdtemp, rm } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { tmpdir } from "node:os";
import type { Finding, ScanResult } from "@synsec/core";
import type { ScannerAdapter, ScannerAvailability, ScannerContext } from "@synsec/scanner-sdk";
import { runProcess } from "@synsec/scanner-sdk";
import { asArray, asNumber, asRecord, asString, commandAvailability, normalizeSeverity, relativeLike, safeJson } from "./utils.js";

const MAX_CHANGED_FILES = 500;

export function normalizeTrivyChangedFiles(files: readonly string[] | undefined): string[] | undefined {
  if (files === undefined) return undefined;
  if (files.length === 0) return [];
  if (files.length > MAX_CHANGED_FILES) {
    throw new Error(`Trivy changed-file scope exceeds the ${MAX_CHANGED_FILES}-file adapter limit.`);
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
      throw new Error("Trivy changed-file scope contains an unsafe repository path.");
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
  return { staged: true };
}

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
    const changedFiles = normalizeTrivyChangedFiles(context.changedFiles);
    if (changedFiles && changedFiles.length === 0) {
      return {
        scanner: this.id,
        startedAt,
        completedAt: new Date().toISOString(),
        target: context.target,
        findings: [],
        diagnostics: ["Changed-file scope is empty; Trivy was not invoked."],
      };
    }

    const temp = await mkdtemp(join(tmpdir(), "synsec-trivy-"));
    try {
      let target = context.target.path;
      let parseRoot = context.target.path;
      const diagnostics: string[] = [];
      if (changedFiles) {
        const stagingRoot = join(temp, "scope");
        const staged = await stageChangedFiles(context.target.path, stagingRoot, changedFiles);
        if (staged.staged) {
          target = stagingRoot;
          parseRoot = stagingRoot;
          diagnostics.push(`Trivy scanned ${changedFiles.length} staged changed file(s) with repository-relative paths preserved.`);
        } else {
          diagnostics.push(`Trivy changed-file staging was unsafe or ambiguous (${staged.reason}); fell back to a full repository scan.`);
        }
      }

      const output = await runProcess("trivy", ["fs", "--format", "json", "--scanners", "vuln,secret,misconfig", target], {
        cwd: context.target.path,
        timeoutMs: context.timeoutMs ?? 10 * 60_000,
        signal: context.signal,
      });
      if (output.exitCode !== 0) throw new Error(`Trivy scan failed (${output.exitCode}): ${output.stderr.trim()}`);
      if (output.stderr.trim()) diagnostics.push(output.stderr.trim());
      return {
        scanner: this.id,
        startedAt,
        completedAt: new Date().toISOString(),
        target: context.target,
        findings: parseTrivyJson(output.stdout, parseRoot),
        diagnostics,
      };
    } finally {
      await rm(temp, { recursive: true, force: true });
    }
  }
}
