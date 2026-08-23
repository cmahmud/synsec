import assert from "node:assert/strict";
import test from "node:test";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import {
  REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES,
} from "@synsec/github/app-deployment";
import {
  GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS,
} from "@synsec/github/shared-state-conformance";

const exec = promisify(execFile);
const cli = new URL("../apps/cli/dist/github-app-shared-state-evidence-cli.js", import.meta.url);

function createContract(overrides = {}) {
  return {
    contractVersion: 1,
    backendId: "postgres-v1",
    implementationVersion: "0.2.0-build.42",
    capabilities: Object.fromEntries(
      REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES.map((capability) => [capability, true]),
    ),
    evidence: REQUIRED_GITHUB_APP_SHARED_STATE_CAPABILITIES.map((capability) => ({
      capability,
      mechanism: "shared-durable-store",
      reference: `conformance-${capability}`,
    })),
    ...overrides,
  };
}

function createReport(overrides = {}) {
  const coveredScenarioIds = GITHUB_APP_SHARED_STATE_CONFORMANCE_SCENARIOS.map((scenario) => scenario.id);
  return {
    schemaVersion: 1,
    backendId: "postgres-v1",
    implementationVersion: "0.2.0-build.42",
    complete: true,
    scenarioTimeoutMs: 5000,
    results: coveredScenarioIds.map((id) => ({ id, status: "passed", durationMs: 1 })),
    coverage: {
      complete: true,
      coveredScenarioIds,
      missingScenarioIds: [],
      missingCapabilities: [],
    },
    ...overrides,
  };
}

async function runExpectingExit(args, expectedCode) {
  try {
    await exec(process.execPath, [cli.pathname, ...args]);
    assert.fail(`Expected exit code ${expectedCode}.`);
  } catch (error) {
    assert.equal(error.code, expectedCode);
    return error;
  }
}

test("shared-state evidence CLI accepts complete identity-bound evidence", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-shared-state-evidence-cli-"));
  try {
    const contractPath = join(root, "contract.json");
    const reportPath = join(root, "report.json");
    await writeFile(contractPath, JSON.stringify(createContract()), "utf8");
    await writeFile(reportPath, JSON.stringify(createReport()), "utf8");

    const { stdout } = await exec(process.execPath, [cli.pathname, contractPath, reportPath, "--json"]);
    const output = JSON.parse(stdout);
    assert.equal(output.ready, true);
    assert.deepEqual(output.issues, []);
    assert.deepEqual(output.missingScenarioIds, []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("shared-state evidence CLI exits 2 on stale adapter evidence", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-shared-state-evidence-stale-"));
  try {
    const contractPath = join(root, "contract.json");
    const reportPath = join(root, "report.json");
    await writeFile(contractPath, JSON.stringify(createContract({ implementationVersion: "0.2.0-build.43" })), "utf8");
    await writeFile(reportPath, JSON.stringify(createReport()), "utf8");

    const error = await runExpectingExit([contractPath, reportPath, "--json"], 2);
    const output = JSON.parse(error.stdout);
    assert.equal(output.ready, false);
    assert.deepEqual(output.issues.map((issue) => issue.code), ["implementation-version-mismatch"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("shared-state evidence CLI does not echo credential-shaped invalid contract values", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-shared-state-evidence-secret-"));
  try {
    const contractPath = join(root, "contract.json");
    const reportPath = join(root, "report.json");
    const secret = "postgres://user:must-not-echo@db.internal/synsec";
    await writeFile(contractPath, JSON.stringify(createContract({ backendId: secret })), "utf8");
    await writeFile(reportPath, JSON.stringify(createReport()), "utf8");

    const error = await runExpectingExit([contractPath, reportPath, "--json"], 2);
    assert.doesNotMatch(error.stdout, /must-not-echo|db\.internal/);
    assert.doesNotMatch(error.stderr, /must-not-echo|db\.internal/);
    assert.equal(JSON.parse(error.stdout).issues[0].code, "invalid-backend-contract");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("shared-state evidence CLI rejects malformed JSON without echoing file contents", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-shared-state-evidence-json-"));
  try {
    const contractPath = join(root, "contract.json");
    const reportPath = join(root, "report.json");
    await writeFile(contractPath, '{"password":"must-not-echo"', "utf8");
    await writeFile(reportPath, JSON.stringify(createReport()), "utf8");

    const error = await runExpectingExit([contractPath, reportPath], 1);
    assert.match(error.stderr, /must contain valid JSON/);
    assert.doesNotMatch(error.stderr, /must-not-echo/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("shared-state evidence CLI rejects unsupported or duplicate flags", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-shared-state-evidence-flags-"));
  try {
    const contractPath = join(root, "contract.json");
    const reportPath = join(root, "report.json");
    await writeFile(contractPath, JSON.stringify(createContract()), "utf8");
    await writeFile(reportPath, JSON.stringify(createReport()), "utf8");

    let error = await runExpectingExit([contractPath, reportPath, "--jsno"], 1);
    assert.match(error.stderr, /Usage:/);
    error = await runExpectingExit([contractPath, reportPath, "--json", "--json"], 1);
    assert.match(error.stderr, /Usage:/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
