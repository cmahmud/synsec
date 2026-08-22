#!/usr/bin/env node

import { copyFile, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { reviewFinding, type AiFindingReview } from "@synsec/ai";
import {
  loadConfig,
  resolveReportPaths,
  SYNSEC_CONFIG_FILENAME,
  writeDefaultConfig,
  type SynSecConfig,
} from "@synsec/config";
import type { CorrelatedFinding } from "@synsec/core";
import { runScanEngine, scannerStatuses } from "@synsec/engine";
import {
  buildReport,
  readReport,
  renderHtml,
  toSarif,
  writeHtml,
  writeReport,
  writeSarif,
  type SynSecReport,
} from "@synsec/report";
import { getFindingContext } from "@synsec/repository";
import { parseSarifJson } from "@synsec/scanners";
import {
  assertWorkflowSourceContextAllowed,
  builtInWorkflows,
  getWorkflow,
  workflowFindings,
  type WorkflowDefinition,
} from "@synsec/workflows";

const VERSION = "0.2.0";
const args = process.argv.slice(2);
const command = args[0] ?? "help";

function option(name: string): string | undefined {
  const index = args.indexOf(name);
  if (index >= 0) return args[index + 1];
  const prefix = `${name}=`;
  const inline = args.find((value) => value.startsWith(prefix));
  return inline?.slice(prefix.length);
}

function flag(name: string): boolean {
  return args.includes(name);
}

function integerOption(name: string): number | undefined {
  const raw = option(name);
  if (raw === undefined) return undefined;
  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value) || value <= 0) throw new Error(`${name} must be a positive integer.`);
  return value;
}

function severityOption(name: string): SynSecConfig["failOn"] | undefined {
  const value = option(name);
  if (value === undefined) return undefined;
  if (
    value === "critical" ||
    value === "high" ||
    value === "medium" ||
    value === "low" ||
    value === "info" ||
    value === "unknown" ||
    value === "none"
  ) return value;
  throw new Error(`${name} must be one of critical, high, medium, low, info, unknown, none.`);
}

function workflowOption(): WorkflowDefinition | undefined {
  const id = option("--workflow");
  if (!id) return undefined;
  const workflow = getWorkflow(id);
  if (!workflow) {
    throw new Error(
      `Unknown workflow ${id}. Available workflows: ${builtInWorkflows().map((item) => item.id).join(", ")}`,
    );
  }
  return workflow;
}

function printHelp(): void {
  console.log(`SynSec v${VERSION} — repository-first security scanning

Usage:
  synsec init [path]
  synsec doctor [path] [--config <file>]
  synsec scan <path> [options]
  synsec review <report.json> [options]
  synsec import-sarif <input.sarif> [options]
  synsec workflows
  synsec render <report.json> [--html <file>] [--sarif <file>]
  synsec baseline <report.json> [destination]
  synsec version

Scan options:
  --config <file>          Use an explicit synsec.config.json.
  --scanners <a,b,c>      Override enabled scanners for this run.
  --parallel <n>           Maximum scanners running at once.
  --timeout <seconds>      Per-scanner timeout.
  --fail-on <severity>     Exit non-zero when this severity or higher is found.
  --baseline <report>      Compare against a previous SynSec report.
  --json                   Print the report JSON to stdout.
  --no-write               Do not write JSON/HTML/SARIF report files.
  --ai                     Run optional AI triage after deterministic scanning.
  --workflow <id>          Restrict AI triage to a built-in defensive workflow.
  --ai-source              Allow source excerpts when the selected workflow permits it.
  --ai-limit <n>           Maximum findings to review (default: 10).
  --ai-base-url <url>      OpenAI-compatible API base URL.
  --ai-model <model>       Model ID for AI triage.

Review options:
  --root <path>            Repository root when it differs from the saved report path.
  --output <file>          AI review output path.
  --workflow <id>          Restrict review to a built-in defensive workflow.
  --ai-source              Allow bounded source excerpts when the workflow permits it.
  --ai-limit <n>           Maximum findings to review.
  --ai-base-url <url>      OpenAI-compatible API base URL.
  --ai-model <model>       Model ID.

SARIF import options:
  --root <path>            Repository root represented by the imported findings (default: .).
  --output <file>          SynSec JSON report path (default: .synsec/imported-report.json).
  --html <file>            HTML report path (default: next to the JSON report).
  --scanner <name>         Override the source scanner name for all imported findings.

AI environment variables:
  SYNSEC_AI_BASE_URL
  SYNSEC_AI_API_KEY
  SYNSEC_AI_MODEL

SynSec never enables AI review by default. Source excerpts are only sent when
sendSourceContext is enabled in config or --ai-source is explicitly supplied.
Workflow capability rules can further prohibit source context.
`);
}

async function ensureDirectory(path: string): Promise<string> {
  const root = resolve(path);
  const info = await stat(root).catch(() => undefined);
  if (!info?.isDirectory()) throw new Error(`Not a directory: ${root}`);
  return root;
}

async function configFor(root: string): Promise<{ config: SynSecConfig; path?: string }> {
  const loaded = await loadConfig(root, option("--config"));
  const config = structuredClone(loaded.config);

  const scanners = option("--scanners");
  if (scanners) config.scanners = scanners.split(",").map((value) => value.trim()).filter(Boolean);

  const parallelism = integerOption("--parallel");
  if (parallelism) config.parallelism = parallelism;

  const timeoutSeconds = integerOption("--timeout");
  if (timeoutSeconds) config.timeoutMs = timeoutSeconds * 1000;

  const failOn = severityOption("--fail-on");
  if (failOn) config.failOn = failOn;

  if (flag("--ai")) config.ai.enabled = true;
  if (flag("--ai-source")) config.ai.sendSourceContext = true;
  const baseUrl = option("--ai-base-url");
  if (baseUrl) config.ai.baseUrl = baseUrl;
  const model = option("--ai-model");
  if (model) config.ai.model = model;

  return loaded.path ? { config, path: loaded.path } : { config };
}

async function init(): Promise<void> {
  const root = await ensureDirectory(args[1] && !args[1].startsWith("--") ? args[1] : ".");
  const path = resolve(root, SYNSEC_CONFIG_FILENAME);
  try {
    await writeDefaultConfig(path);
  } catch (error) {
    const code = typeof error === "object" && error !== null && "code" in error ? String((error as { code?: unknown }).code) : "";
    if (code === "EEXIST") throw new Error(`${path} already exists.`);
    throw error;
  }
  console.log(`Created ${path}`);
}

async function doctor(): Promise<void> {
  const root = await ensureDirectory(args[1] && !args[1].startsWith("--") ? args[1] : ".");
  const { config, path } = await configFor(root);
  console.log(`SynSec v${VERSION}`);
  console.log(`Config: ${path ?? "defaults"}`);
  console.log(`Parallelism: ${config.parallelism}\n`);

  const statuses = await scannerStatuses(config);
  for (const status of statuses) {
    const marker = !status.selected ? "DISABLED" : status.availability.available ? "OK" : "MISSING";
    const detail = status.availability.version ?? status.availability.reason ?? "";
    console.log(`${marker.padEnd(9)} ${status.displayName.padEnd(20)} ${detail}`);
  }

  console.log("\nAI review:");
  console.log(`  ${config.ai.enabled ? "enabled" : "disabled"} (source context ${config.ai.sendSourceContext ? "allowed" : "not allowed"})`);
}

function listWorkflows(): void {
  console.log("SynSec defensive workflows\n");
  for (const workflow of builtInWorkflows()) {
    const categories = workflow.categories === "all" ? "all findings" : workflow.categories.join(", ");
    console.log(`${workflow.id}`);
    console.log(`  ${workflow.description}`);
    console.log(`  categories: ${categories}`);
    console.log(`  source context: ${workflow.sourceContextAllowed ? "may be explicitly enabled" : "prohibited"}`);
    console.log(`  external network assessment: ${workflow.externalNetworkAssessment}\n`);
  }
}

function printFinding(group: CorrelatedFinding): void {
  const finding = group.primary;
  const location = finding.location
    ? `${finding.location.path}${finding.location.startLine ? `:${finding.location.startLine}` : ""}`
    : "repository";
  const sources = group.sources.map((source) => source.name).join(", ");
  console.log(`[${finding.severity.toUpperCase()}] ${finding.title}`);
  console.log(`  ${location}`);
  console.log(`  sources: ${sources}`);
  if (finding.remediation) console.log(`  fix: ${finding.remediation}`);
  console.log("");
}

function aiProvider(config: SynSecConfig): { baseUrl: string; apiKey?: string; model: string } {
  const baseUrl = config.ai.baseUrl ?? process.env.SYNSEC_AI_BASE_URL;
  const model = config.ai.model ?? process.env.SYNSEC_AI_MODEL;
  const apiKey = process.env.SYNSEC_AI_API_KEY;
  if (!baseUrl) throw new Error("AI review is enabled but no base URL is configured. Set SYNSEC_AI_BASE_URL or --ai-base-url.");
  if (!model) throw new Error("AI review is enabled but no model is configured. Set SYNSEC_AI_MODEL or --ai-model.");
  return apiKey ? { baseUrl, model, apiKey } : { baseUrl, model };
}

async function reviewGroups(
  report: SynSecReport,
  root: string,
  config: SynSecConfig,
  limit: number,
  workflow?: WorkflowDefinition,
): Promise<Record<string, AiFindingReview>> {
  if (workflow) assertWorkflowSourceContextAllowed(workflow, config.ai.sendSourceContext);
  const reviews: Record<string, AiFindingReview> = {};
  const eligible = workflow ? workflowFindings(report.findings, workflow) : report.findings;
  const candidates = eligible.slice(0, limit);
  if (candidates.length === 0) return reviews;
  const provider = aiProvider(config);

  for (let index = 0; index < candidates.length; index += 1) {
    const group = candidates[index];
    if (!group) continue;
    const workflowLabel = workflow ? ` [${workflow.id}]` : "";
    console.error(`AI review${workflowLabel} ${index + 1}/${candidates.length}: ${group.primary.title}`);
    const context = config.ai.sendSourceContext
      ? await getFindingContext(root, group.primary)
      : undefined;
    reviews[group.fingerprint] = await reviewFinding(group.primary, provider, context);
  }
  return reviews;
}

async function writeAiReviews(
  path: string,
  report: SynSecReport,
  reviews: Record<string, AiFindingReview>,
  workflow?: WorkflowDefinition,
): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(
    path,
    `${JSON.stringify({
      schemaVersion: 1,
      reportId: report.reportId,
      generatedAt: new Date().toISOString(),
      workflow: workflow ? { id: workflow.id, version: workflow.version } : null,
      reviews,
    }, null, 2)}\n`,
    "utf8",
  );
}

async function scan(): Promise<void> {
  const targetArg = args[1];
  if (!targetArg || targetArg.startsWith("--")) throw new Error("Usage: synsec scan <path> [options]");
  const root = await ensureDirectory(targetArg);
  const { config, path: configPath } = await configFor(root);

  const baselinePath = option("--baseline") ?? config.baseline;
  const baseline = baselinePath ? await readReport(resolve(root, baselinePath)) : undefined;

  if (!flag("--json")) {
    console.error(`SynSec v${VERSION}`);
    console.error(`Target: ${root}`);
    console.error(`Config: ${configPath ?? "defaults"}`);
    console.error(`Scanners: ${config.scanners.join(", ")}\n`);
  }

  const outcome = await runScanEngine({
    rootPath: root,
    config,
    baseline,
    toolVersion: VERSION,
  });

  const paths = resolveReportPaths(root, config);
  if (!flag("--no-write")) {
    await Promise.all([
      writeReport(paths.json, outcome.report),
      writeHtml(paths.html, outcome.report),
      writeSarif(paths.sarif, outcome.report),
    ]);
  }

  if (config.ai.enabled) {
    const limit = integerOption("--ai-limit") ?? 10;
    const workflow = workflowOption();
    const reviews = await reviewGroups(outcome.report, root, config, limit, workflow);
    const aiPath = resolve(root, ".synsec/ai-review.json");
    await writeAiReviews(aiPath, outcome.report, reviews, workflow);
    if (!flag("--json")) console.error(`AI reviews: ${aiPath}`);
  } else if (option("--workflow")) {
    throw new Error("--workflow is an AI review option. Enable review with --ai or in synsec.config.json.");
  }

  if (flag("--json")) {
    process.stdout.write(`${JSON.stringify(outcome.report, null, 2)}\n`);
  } else {
    console.log(`Security score: ${outcome.report.securityScore}/100`);
    console.log(
      `Findings: ${outcome.report.findingCount} correlated (${outcome.report.rawFindingCount} raw) — ` +
      `${outcome.report.summary.critical} critical, ${outcome.report.summary.high} high, ` +
      `${outcome.report.summary.medium} medium, ${outcome.report.summary.low} low\n`,
    );
    const sbomPackages = (outcome.report.artifacts ?? [])
      .filter((artifact) => artifact.type === "sbom")
      .reduce((total, artifact) => total + artifact.packageCount, 0);
    if (sbomPackages > 0) console.log(`SBOM: ${sbomPackages} package(s) inventoried\n`);

    if (outcome.report.baseline) {
      console.log(
        `Since baseline: ${outcome.report.baseline.new.length} new, ${outcome.report.baseline.fixed.length} fixed, ${outcome.report.baseline.persisting.length} persisting\n`,
      );
    }

    for (const group of outcome.report.findings) printFinding(group);

    for (const failure of outcome.failures) {
      console.error(`Scanner failed: ${failure.scanner}: ${failure.message}`);
    }
    const missing = outcome.statuses.filter((status) => status.selected && !status.availability.available);
    for (const status of missing) {
      console.error(`Scanner unavailable: ${status.displayName}: ${status.availability.reason ?? "not installed"}`);
    }

    if (!flag("--no-write")) {
      console.log(`JSON:  ${paths.json}`);
      console.log(`HTML:  ${paths.html}`);
      console.log(`SARIF: ${paths.sarif}`);
    }
  }

  if (outcome.shouldFail) process.exitCode = 2;
}

async function review(): Promise<void> {
  const reportArg = args[1];
  if (!reportArg || reportArg.startsWith("--")) throw new Error("Usage: synsec review <report.json> [options]");
  const reportPath = resolve(reportArg);
  const report = await readReport(reportPath);
  const root = await ensureDirectory(option("--root") ?? report.target.path);
  const { config } = await configFor(root);
  config.ai.enabled = true;
  if (flag("--ai-source")) config.ai.sendSourceContext = true;
  const baseUrl = option("--ai-base-url");
  if (baseUrl) config.ai.baseUrl = baseUrl;
  const model = option("--ai-model");
  if (model) config.ai.model = model;
  const workflow = workflowOption();
  const limit = integerOption("--ai-limit") ?? report.findings.length;
  const reviews = await reviewGroups(report, root, config, limit, workflow);
  const explicitOutput = option("--output");
  const outputPath = explicitOutput ? resolve(explicitOutput) : resolve(dirname(reportPath), "ai-review.json");
  await writeAiReviews(outputPath, report, reviews, workflow);
  console.log(`Wrote ${Object.keys(reviews).length} AI review(s) to ${outputPath}`);
}

async function importSarif(): Promise<void> {
  const inputArg = args[1];
  if (!inputArg || inputArg.startsWith("--")) {
    throw new Error("Usage: synsec import-sarif <input.sarif> [--root <path>] [--output <file>] [--scanner <name>]");
  }
  const inputPath = resolve(inputArg);
  const root = await ensureDirectory(option("--root") ?? ".");
  const raw = await readFile(inputPath, "utf8");
  const scannerOverride = option("--scanner");
  const findings = parseSarifJson(raw, scannerOverride);
  const now = new Date().toISOString();
  const report = buildReport({
    target: { path: root },
    scans: [{
      scanner: scannerOverride ?? "sarif-import",
      startedAt: now,
      completedAt: now,
      target: { path: root },
      findings,
      diagnostics: [],
    }],
    toolVersion: VERSION,
  });

  const outputPath = resolve(option("--output") ?? resolve(root, ".synsec/imported-report.json"));
  const htmlPath = resolve(option("--html") ?? outputPath.replace(/\.json$/i, ".html"));
  await Promise.all([
    writeReport(outputPath, report),
    writeHtml(htmlPath, report),
  ]);
  console.log(`Imported ${findings.length} SARIF finding(s).`);
  console.log(`JSON: ${outputPath}`);
  console.log(`HTML: ${htmlPath}`);
}

async function render(): Promise<void> {
  const reportArg = args[1];
  if (!reportArg || reportArg.startsWith("--")) throw new Error("Usage: synsec render <report.json> [--html <file>] [--sarif <file>]");
  const reportPath = resolve(reportArg);
  const report = await readReport(reportPath);
  const htmlPath = resolve(option("--html") ?? reportPath.replace(/\.json$/i, ".html"));
  const sarifPath = resolve(option("--sarif") ?? reportPath.replace(/\.json$/i, ".sarif"));
  await Promise.all([
    mkdir(dirname(htmlPath), { recursive: true }).then(() => writeFile(htmlPath, renderHtml(report), "utf8")),
    mkdir(dirname(sarifPath), { recursive: true }).then(() => writeFile(sarifPath, `${JSON.stringify(toSarif(report), null, 2)}\n`, "utf8")),
  ]);
  console.log(`HTML:  ${htmlPath}`);
  console.log(`SARIF: ${sarifPath}`);
}

async function baseline(): Promise<void> {
  const source = args[1];
  if (!source || source.startsWith("--")) throw new Error("Usage: synsec baseline <report.json> [destination]");
  await readReport(resolve(source));
  const destination = resolve(args[2] && !args[2].startsWith("--") ? args[2] : ".synsec/baseline.json");
  await mkdir(dirname(destination), { recursive: true });
  await copyFile(resolve(source), destination);
  console.log(`Baseline saved to ${destination}`);
}

async function main(): Promise<void> {
  switch (command) {
    case "init":
      await init();
      break;
    case "doctor":
      await doctor();
      break;
    case "scan":
      await scan();
      break;
    case "review":
      await review();
      break;
    case "import-sarif":
      await importSarif();
      break;
    case "workflows":
      listWorkflows();
      break;
    case "render":
      await render();
      break;
    case "baseline":
      await baseline();
      break;
    case "version":
    case "--version":
    case "-v":
      console.log(VERSION);
      break;
    case "help":
    case "--help":
    case "-h":
      printHelp();
      break;
    default:
      printHelp();
      process.exitCode = 1;
  }
}

main().catch((error: unknown) => {
  console.error(`SynSec error: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
