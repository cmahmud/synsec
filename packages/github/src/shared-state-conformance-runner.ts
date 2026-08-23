import {
  GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS,
  assessGitHubAppSharedStateConformanceCoverage,
  type GitHubAppSharedStateConformanceCoverageAssessment,
} from "./shared-state-conformance.js";

const DEFAULT_SCENARIO_TIMEOUT_MS = 15_000;
const MIN_SCENARIO_TIMEOUT_MS = 100;
const MAX_SCENARIO_TIMEOUT_MS = 120_000;

export type GitHubAppSharedStateConformanceScenarioId =
  (typeof GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS)[number]["id"];

export interface GitHubAppSharedStateConformanceAdapter {
  /**
   * Reset adapter-owned test state before a scenario. This hook must be safe to run repeatedly.
   * Credentials and connection strings remain adapter-private and must not be returned.
   */
  reset(): Promise<void>;
  scenarios: Readonly<Record<GitHubAppSharedStateConformanceScenarioId, () => Promise<void>>>;
}

export interface GitHubAppSharedStateConformanceRunOptions {
  scenarioTimeoutMs?: number;
  now?: () => number;
}

export interface GitHubAppSharedStateConformanceScenarioResult {
  id: GitHubAppSharedStateConformanceScenarioId;
  status: "passed" | "failed" | "timed-out";
  durationMs: number;
}

export interface GitHubAppSharedStateConformanceRunReport {
  schemaVersion: 1;
  complete: boolean;
  scenarioTimeoutMs: number;
  results: GitHubAppSharedStateConformanceScenarioResult[];
  coverage: GitHubAppSharedStateConformanceCoverageAssessment;
}

function validatedTimeout(value: number | undefined): number {
  const timeout = value ?? DEFAULT_SCENARIO_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeout) || timeout < MIN_SCENARIO_TIMEOUT_MS || timeout > MAX_SCENARIO_TIMEOUT_MS) {
    throw new Error(
      `Shared-state conformance scenario timeout must be an integer between ${MIN_SCENARIO_TIMEOUT_MS} and ${MAX_SCENARIO_TIMEOUT_MS} milliseconds.`,
    );
  }
  return timeout;
}

function validateAdapter(adapter: GitHubAppSharedStateConformanceAdapter): void {
  if (!adapter || typeof adapter !== "object") {
    throw new Error("Shared-state conformance adapter is required.");
  }
  if (typeof adapter.reset !== "function") {
    throw new Error("Shared-state conformance adapter reset() is required.");
  }
  if (!adapter.scenarios || typeof adapter.scenarios !== "object") {
    throw new Error("Shared-state conformance adapter scenarios are required.");
  }

  const requiredIds = new Set<string>(
    GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.map((scenario) => scenario.id),
  );
  const suppliedIds = Object.keys(adapter.scenarios);
  const missing = [...requiredIds].filter((id) => typeof adapter.scenarios[id as GitHubAppSharedStateConformanceScenarioId] !== "function");
  const unknown = suppliedIds.filter((id) => !requiredIds.has(id));
  if (missing.length > 0 || unknown.length > 0) {
    throw new Error("Shared-state conformance adapter must implement exactly the required scenario ids.");
  }
}

async function runWithTimeout(
  operation: () => Promise<void>,
  timeoutMs: number,
): Promise<"passed" | "failed" | "timed-out"> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      Promise.resolve()
        .then(operation)
        .then(() => "passed" as const, () => "failed" as const),
      new Promise<"timed-out">((resolve) => {
        timer = setTimeout(() => resolve("timed-out"), timeoutMs);
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Execute the canonical shared-state adversarial matrix against an adapter-provided real backend.
 *
 * Scenarios run sequentially and are reset independently so one failed scenario cannot manufacture
 * evidence for another. Failure details are intentionally excluded from the report: database errors
 * can contain credentials, hostnames, queries, or customer data. Adapter test harnesses may log their
 * own sanitized diagnostics separately.
 *
 * A passing report is evidence that these callbacks completed; it is not backend certification by
 * itself. Production claims should bind the report to the exact adapter/backend version in CI.
 */
export async function runGitHubAppSharedStateConformance(
  adapter: GitHubAppSharedStateConformanceAdapter,
  options: GitHubAppSharedStateConformanceRunOptions = {},
): Promise<GitHubAppSharedStateConformanceRunReport> {
  validateAdapter(adapter);
  const scenarioTimeoutMs = validatedTimeout(options.scenarioTimeoutMs);
  const now = options.now ?? Date.now;
  const results: GitHubAppSharedStateConformanceScenarioResult[] = [];

  for (const scenario of GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS) {
    const startedAt = now();
    let status: GitHubAppSharedStateConformanceScenarioResult["status"];
    try {
      await adapter.reset();
      status = await runWithTimeout(adapter.scenarios[scenario.id], scenarioTimeoutMs);
    } catch {
      status = "failed";
    }
    const finishedAt = now();
    results.push({
      id: scenario.id,
      status,
      durationMs: Math.max(0, Math.min(Number.MAX_SAFE_INTEGER, Math.trunc(finishedAt - startedAt))),
    });
  }

  const completedScenarioIds = results
    .filter((result) => result.status === "passed")
    .map((result) => result.id);
  const coverage = assessGitHubAppSharedStateConformanceCoverage(completedScenarioIds);

  return {
    schemaVersion: 1,
    complete: coverage.complete,
    scenarioTimeoutMs,
    results,
    coverage,
  };
}
