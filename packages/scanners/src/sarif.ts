import { randomUUID } from "node:crypto";
import type { Finding, FindingCategory, Severity } from "@synsec/core";
import { asArray, asNumber, asRecord, asString, identifiersFrom, relativeLike, safeJson } from "./utils.js";

const categories = new Set<FindingCategory>([
  "sast",
  "dependency",
  "secret",
  "misconfiguration",
  "iac",
  "container",
  "supply-chain",
  "repository-posture",
  "license",
  "other",
]);

function severityFrom(value: unknown): Severity {
  const normalized = asString(value)?.toLowerCase();
  if (normalized === "critical" || normalized === "high" || normalized === "medium" || normalized === "low" || normalized === "info" || normalized === "unknown") return normalized;
  if (normalized === "error") return "high";
  if (normalized === "warning") return "medium";
  if (normalized === "note") return "low";
  if (normalized === "none") return "info";
  return "unknown";
}

function categoryFrom(value: unknown): FindingCategory {
  const category = asString(value) as FindingCategory | undefined;
  return category && categories.has(category) ? category : "other";
}

function text(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  const record = asRecord(value);
  return asString(record?.text) ?? asString(record?.markdown);
}

function nativeFingerprint(result: Record<string, unknown>): string | undefined {
  const partial = asRecord(result.partialFingerprints);
  if (!partial) return undefined;
  for (const value of Object.values(partial)) {
    if (typeof value === "string" && value.trim()) return value;
  }
  return undefined;
}

function sarifRepositoryPath(uri: string | undefined, root: string): string | undefined {
  if (!uri) return undefined;
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(uri)) {
    if (!uri.toLowerCase().startsWith("file:")) return undefined;
    try {
      let pathname = decodeURIComponent(new URL(uri).pathname).replace(/\\/g, "/");
      if (/^\/[A-Za-z]:\//.test(pathname)) pathname = pathname.slice(1);
      return relativeLike(pathname, root);
    } catch {
      return undefined;
    }
  }
  return relativeLike(uri, root);
}

function firstLocation(result: Record<string, unknown>, root: string): Finding["location"] {
  const location = asRecord(asArray(result.locations)[0]);
  const physical = asRecord(location?.physicalLocation);
  const artifact = asRecord(physical?.artifactLocation);
  const region = asRecord(physical?.region);
  const path = sarifRepositoryPath(asString(artifact?.uri), root);
  if (!path) return undefined;
  return {
    path,
    startLine: asNumber(region?.startLine),
    endLine: asNumber(region?.endLine),
    startColumn: asNumber(region?.startColumn),
    endColumn: asNumber(region?.endColumn),
  };
}

function ruleMap(run: Record<string, unknown>): Map<string, Record<string, unknown>> {
  const tool = asRecord(run.tool);
  const driver = asRecord(tool?.driver);
  const map = new Map<string, Record<string, unknown>>();
  for (const value of asArray(driver?.rules)) {
    const rule = asRecord(value);
    const id = asString(rule?.id);
    if (rule && id) map.set(id, rule);
  }
  return map;
}

export function parseSarifJson(raw: string, scannerOverride?: string, root = ""): Finding[] {
  const parsed = asRecord(safeJson(raw));
  if (!parsed || asString(parsed.version) !== "2.1.0") {
    throw new Error("SARIF import requires a SARIF 2.1.0 document.");
  }

  const findings: Finding[] = [];
  for (const runValue of asArray(parsed.runs)) {
    const run = asRecord(runValue);
    if (!run) continue;
    const tool = asRecord(run.tool);
    const driver = asRecord(tool?.driver);
    const scannerName = scannerOverride ?? asString(driver?.name) ?? "sarif-import";
    const rules = ruleMap(run);

    for (const resultValue of asArray(run.results)) {
      const result = asRecord(resultValue);
      if (!result) continue;
      const ruleId = asString(result.ruleId);
      const rule = ruleId ? rules.get(ruleId) : undefined;
      const properties = asRecord(result.properties);
      const ruleProperties = asRecord(rule?.properties);
      const message = text(result.message);
      const title = message ?? text(rule?.shortDescription) ?? ruleId ?? "Imported SARIF finding";
      const description = text(rule?.fullDescription) ?? text(rule?.shortDescription);
      const identifiers = asArray(ruleProperties?.identifiers).filter((item): item is string => typeof item === "string");
      const confidence = asNumber(properties?.confidence);
      const finding: Finding = {
        id: randomUUID(),
        title,
        description,
        category: categoryFrom(properties?.category ?? ruleProperties?.category),
        severity: severityFrom(properties?.severity ?? result.level ?? ruleProperties?.severity),
        confidence: confidence !== undefined && confidence >= 0 && confidence <= 1 ? confidence : 0.8,
        scanner: { name: scannerName, ruleId },
        location: firstLocation(result, root),
        identifiers: identifiersFrom(identifiers),
        remediation: asString(properties?.remediation) ?? text(rule?.help),
        fingerprint: nativeFingerprint(result),
        metadata: {
          sarifRuleIndex: asNumber(result.ruleIndex),
          sarifToolVersion: asString(driver?.semanticVersion) ?? asString(driver?.version),
        },
      };
      findings.push(finding);
    }
  }
  return findings;
}
