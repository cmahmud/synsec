import { access, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { Severity } from "@synsec/core";

export const SYNSEC_CONFIG_FILENAME = "synsec.config.json";

export interface AiConfig {
  enabled: boolean;
  provider: "openai-compatible";
  baseUrl?: string;
  model?: string;
  sendSourceContext: boolean;
}

export interface ReportConfig {
  json: string;
  html: string;
  sarif: string;
}

export interface SynSecConfig {
  schemaVersion: 1;
  scanners: string[];
  parallelism: number;
  timeoutMs: number;
  failOn: Severity | "none";
  reports: ReportConfig;
  baseline?: string;
  ai: AiConfig;
}

export const defaultConfig: SynSecConfig = {
  schemaVersion: 1,
  scanners: [
    "opengrep",
    "betterleaks",
    "osv-scanner",
    "trivy",
    "grype",
    "checkov",
    "syft",
    "scorecard",
  ],
  parallelism: 3,
  timeoutMs: 15 * 60_000,
  failOn: "none",
  reports: {
    json: ".synsec/report.json",
    html: ".synsec/report.html",
    sarif: ".synsec/report.sarif",
  },
  ai: {
    enabled: false,
    provider: "openai-compatible",
    sendSourceContext: false,
  },
};

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function stringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) return undefined;
  return value;
}

function severity(value: unknown): SynSecConfig["failOn"] | undefined {
  if (
    value === "critical" ||
    value === "high" ||
    value === "medium" ||
    value === "low" ||
    value === "info" ||
    value === "unknown" ||
    value === "none"
  ) return value;
  return undefined;
}

function positiveInteger(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : fallback;
}

export function parseConfig(value: unknown): SynSecConfig {
  const root = asRecord(value);
  if (!root) throw new Error("SynSec configuration must be a JSON object.");
  if (root.schemaVersion !== undefined && root.schemaVersion !== 1) {
    throw new Error(`Unsupported SynSec configuration schemaVersion: ${String(root.schemaVersion)}`);
  }

  const reportsValue = asRecord(root.reports);
  const aiValue = asRecord(root.ai);

  const reports: ReportConfig = {
    json: typeof reportsValue?.json === "string" ? reportsValue.json : defaultConfig.reports.json,
    html: typeof reportsValue?.html === "string" ? reportsValue.html : defaultConfig.reports.html,
    sarif: typeof reportsValue?.sarif === "string" ? reportsValue.sarif : defaultConfig.reports.sarif,
  };

  const ai: AiConfig = {
    enabled: typeof aiValue?.enabled === "boolean" ? aiValue.enabled : defaultConfig.ai.enabled,
    provider: "openai-compatible",
    sendSourceContext:
      typeof aiValue?.sendSourceContext === "boolean"
        ? aiValue.sendSourceContext
        : defaultConfig.ai.sendSourceContext,
  };
  if (typeof aiValue?.baseUrl === "string") ai.baseUrl = aiValue.baseUrl;
  if (typeof aiValue?.model === "string") ai.model = aiValue.model;

  const config: SynSecConfig = {
    schemaVersion: 1,
    scanners: stringArray(root.scanners) ?? [...defaultConfig.scanners],
    parallelism: positiveInteger(root.parallelism, defaultConfig.parallelism),
    timeoutMs: positiveInteger(root.timeoutMs, defaultConfig.timeoutMs),
    failOn: severity(root.failOn) ?? defaultConfig.failOn,
    reports,
    ai,
  };
  if (typeof root.baseline === "string") config.baseline = root.baseline;
  return config;
}

export async function findConfig(startPath: string): Promise<string | undefined> {
  const candidate = join(resolve(startPath), SYNSEC_CONFIG_FILENAME);
  return await access(candidate).then(() => candidate).catch(() => undefined);
}

export async function loadConfig(rootPath: string, explicitPath?: string): Promise<{ config: SynSecConfig; path?: string }> {
  const path = explicitPath ? resolve(explicitPath) : await findConfig(rootPath);
  if (!path) return { config: structuredClone(defaultConfig) };
  const parsed = JSON.parse(await readFile(path, "utf8")) as unknown;
  return { config: parseConfig(parsed), path };
}

export async function writeDefaultConfig(path: string): Promise<void> {
  await writeFile(path, `${JSON.stringify(defaultConfig, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
}

export function resolveReportPaths(rootPath: string, config: SynSecConfig): ReportConfig {
  return {
    json: resolve(rootPath, config.reports.json),
    html: resolve(rootPath, config.reports.html),
    sarif: resolve(rootPath, config.reports.sarif),
  };
}
