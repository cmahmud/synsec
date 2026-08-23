import { randomUUID } from "node:crypto";
import { lstatSync, realpathSync } from "node:fs";
import { basename, isAbsolute, relative, resolve, sep } from "node:path";
import type { Finding, ScanResult, Severity } from "@synsec/core";
import type { ScannerAdapter, ScannerAvailability, ScannerContext } from "@synsec/scanner-sdk";
import { runProcess } from "@synsec/scanner-sdk";
import { asArray, asRecord, asString, commandAvailability, cvssSeverity, identifiersFrom, normalizeSeverity, relativeLike, safeJson, strings } from "./utils.js";

const MAX_CHANGED_FILES = 100;
const OSV_LOCKFILE_NAMES = new Set([
  "Cargo.lock",
  "Gemfile.lock",
  "buildscript-gradle.lockfile",
  "bun.lock",
  "composer.lock",
  "go.mod",
  "gradle.lockfile",
  "mix.lock",
  "package-lock.json",
  "pnpm-lock.yaml",
  "poetry.lock",
  "pom.xml",
  "pubspec.lock",
  "requirements.txt",
  "uv.lock",
  "yarn.lock",
]);

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

function normalizedChangedPath(value: string): string | undefined {
  const path = value.replace(/\\/g, "/").replace(/^\.\//, "").trim();
  if (
    !path ||
    isAbsolute(path) ||
    /^[A-Za-z]:\//.test(path) ||
    path === ".." ||
    path.startsWith("../") ||
    path.includes("/../") ||
    path.includes("\0")
  ) return undefined;
  return path;
}

function isSupportedOsvDependencyArtifact(path: string): boolean {
  const name = basename(path);
  return OSV_LOCKFILE_NAMES.has(name)
    || /^requirements(?:[-_.][A-Za-z0-9_.-]+)?\.txt$/i.test(name)
    || /(?:^|\.)spdx(?:\.json|\.ya?ml|\.rdf|\.rdf\.xml)?$/i.test(name)
    || /(?:^|\.)cdx\.(?:json|xml)$/i.test(name)
    || /^bom\.(?:json|xml)$/i.test(name);
}

function safeNativeLockfiles(context: ScannerContext): string[] | undefined {
  const changed = context.changedFiles;
  if (!changed || changed.length === 0) return undefined;
  if (changed.length > MAX_CHANGED_FILES) return undefined;

  const root = realpathSync(context.target.path);
  const rootPrefix = root.endsWith(sep) ? root : `${root}${sep}`;
  const result: string[] = [];
  const seen = new Set<string>();

  for (const raw of changed) {
    const normalized = normalizedChangedPath(raw);
    if (!normalized || !isSupportedOsvDependencyArtifact(normalized)) return undefined;
    if (seen.has(normalized)) continue;

    const absolute = resolve(root, normalized);
    const relativePath = relative(root, absolute);
    if (!relativePath || relativePath === ".." || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) {
      return undefined;
    }

    try {
      const stat = lstatSync(absolute);
      if (!stat.isFile() || stat.isSymbolicLink()) return undefined;
      const real = realpathSync(absolute);
      if (!real.startsWith(rootPrefix)) return undefined;
    } catch {
      return undefined;
    }

    seen.add(normalized);
    result.push(absolute);
  }
  return result.length > 0 ? result : undefined;
}

/**
 * OSV-Scanner can safely narrow execution only when the entire changed-file scope is made up of
 * recognized dependency lockfiles/SBOMs that are regular files inside the repository. Any source,
 * manifest/config ambiguity, missing file, symlink, or oversized scope falls back to recursive
 * repository scanning rather than pretending dependency coverage is complete.
 */
export function buildOsvArguments(context: ScannerContext): string[] {
  const lockfiles = safeNativeLockfiles(context);
  if (!lockfiles) return ["scan", "--format", "json", "source", "-r", context.target.path];
  return [
    "scan",
    "--format",
    "json",
    "source",
    ...lockfiles.map((path) => `--lockfile=${path}`),
  ];
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
      buildOsvArguments(context),
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
