import { appendFile } from "node:fs/promises";
import { resolve } from "node:path";
import { loadConfig } from "@synsec/config";
import { runGitHubActionsRepositoryScan } from "@synsec/github/actions-runner";

function nonEmpty(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed || undefined;
}

function booleanInput(value: string | undefined, fallback: boolean): boolean {
  const normalized = value?.trim().toLowerCase();
  if (!normalized) return fallback;
  if (normalized === "true" || normalized === "1" || normalized === "yes") return true;
  if (normalized === "false" || normalized === "0" || normalized === "no") return false;
  throw new Error(`Expected a boolean action input, received: ${normalized.slice(0, 32)}`);
}

function changedOnlyInput(value: string | undefined): boolean | undefined {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "auto") return undefined;
  if (normalized === "true" || normalized === "1" || normalized === "yes") return true;
  if (normalized === "false" || normalized === "0" || normalized === "no") return false;
  throw new Error("changed-only must be auto, true, or false.");
}

async function writeOutput(name: string, value: string | number | undefined): Promise<void> {
  const path = nonEmpty(process.env.GITHUB_OUTPUT);
  if (!path || value === undefined) return;
  const normalized = String(value).replace(/[\r\n]/g, "");
  await appendFile(path, `${name}=${normalized}\n`, "utf8");
}

async function main(): Promise<void> {
  const workspace = resolve(nonEmpty(process.env.GITHUB_WORKSPACE) ?? process.cwd());
  const token = nonEmpty(process.env.SYNSEC_GITHUB_TOKEN);
  if (!token) throw new Error("The SynSec GitHub Action requires a GitHub token.");

  const configInput = nonEmpty(process.env.SYNSEC_CONFIG_PATH);
  const configPath = configInput ? resolve(workspace, configInput) : undefined;
  const { config } = await loadConfig(workspace, configPath);
  const baselineInput = nonEmpty(process.env.SYNSEC_BASELINE_PATH);
  const baselinePath = baselineInput ? resolve(workspace, baselineInput) : undefined;
  const publishSarif = booleanInput(process.env.SYNSEC_PUBLISH_SARIF, false);
  const changedOnly = changedOnlyInput(process.env.SYNSEC_CHANGED_ONLY);

  const result = await runGitHubActionsRepositoryScan(token, {
    config,
    rootPath: workspace,
    baselinePath,
    changedOnly,
    publishSarif,
    threshold: config.failOn,
  });

  await Promise.all([
    writeOutput("security-score", result.outcome.report.securityScore),
    writeOutput("finding-count", result.outcome.report.findingCount),
    writeOutput("check-run-id", result.publication.publication.id),
    writeOutput("sarif-upload-id", result.sarifPublication?.id),
  ]);

  console.log(
    `SynSec scanned ${result.outcome.report.scope?.mode === "changed-files" ? "changed files" : "the repository"}: `
      + `${result.outcome.report.findingCount} finding(s), security score ${result.outcome.report.securityScore}/100.`,
  );
  if (result.outcome.shouldFail) process.exitCode = 1;
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`SynSec GitHub Action failed: ${message.replace(/[\r\n]+/g, " ").slice(0, 1_000)}`);
  process.exitCode = 1;
});
