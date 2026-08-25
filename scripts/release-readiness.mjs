import { access, readFile } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REQUIRED_CI_MARKERS = [
  "matrix:\n        node: [20, 24]",
  "npm run build",
  "npm run typecheck",
  "npm test",
  "postgres:16-alpine",
  "tests/postgres-shared-state-conformance.test.mjs",
  "tests/postgres-hosted-installation-ownership.test.mjs",
  "tests/oci-scanner-sandbox.test.mjs",
];

const REQUIRED_OPERATOR_DOCS = [
  "docs/GITHUB_APP_UPGRADES.md",
  "docs/GITHUB_APP_SERVICE_MAINTENANCE.md",
  "docs/HOSTED_INSTALLATION_OWNERSHIP.md",
  "docs/HOSTED_INSTALLATION_REVERIFICATION_SWEEPS.md",
];

function issue(code, message, severity) {
  return { code, message, severity };
}

async function exists(path) {
  try {
    await access(path, fsConstants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function isStableSemver(value) {
  return typeof value === "string" && /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value);
}

export async function assessReleaseReadiness(rootDirectory) {
  const root = resolve(rootDirectory);
  const errors = [];
  const blockers = [];

  let packageJson;
  try {
    packageJson = JSON.parse(await readFile(resolve(root, "package.json"), "utf8"));
  } catch {
    errors.push(issue("package-json-invalid", "package.json must exist and contain valid JSON.", "error"));
  }

  if (packageJson) {
    if (!isStableSemver(packageJson.version)) {
      errors.push(issue("package-version-invalid", "Root package version must be a stable semantic version.", "error"));
    }
    if (packageJson.engines?.node !== ">=20") {
      errors.push(issue("node-engine-policy-mismatch", "Root Node.js engine policy must remain >=20 for the current release line.", "error"));
    }
    if (packageJson.private !== true) {
      errors.push(issue("root-package-publishable", "The monorepo root must remain private to prevent accidental npm publication.", "error"));
    }
  }

  const workflowPath = resolve(root, ".github/workflows/ci.yml");
  let workflow;
  try {
    workflow = await readFile(workflowPath, "utf8");
  } catch {
    errors.push(issue("ci-workflow-missing", "The required CI workflow is missing or unreadable.", "error"));
  }
  if (workflow) {
    for (const marker of REQUIRED_CI_MARKERS) {
      if (!workflow.includes(marker)) {
        errors.push(issue("ci-coverage-incomplete", `CI is missing required release validation marker: ${marker}`, "error"));
      }
    }
  }

  for (const document of REQUIRED_OPERATOR_DOCS) {
    if (!(await exists(resolve(root, document)))) {
      errors.push(issue("operator-doc-missing", `Required operator documentation is missing: ${document}`, "error"));
    }
  }

  const hasNpmLock = await exists(resolve(root, "package-lock.json"));
  if (!hasNpmLock) {
    blockers.push(issue(
      "dependency-lockfile-missing",
      "No package-lock.json is committed; dependency installation is not yet reproducible and release tagging must remain blocked.",
      "blocker",
    ));
  } else if (workflow && !workflow.includes("npm ci")) {
    blockers.push(issue(
      "ci-not-using-lockfile",
      "A package-lock.json exists but CI is not using npm ci; reproducible installation is not enforced.",
      "blocker",
    ));
  }

  const result = {
    schemaVersion: 1,
    releaseVersion: packageJson?.version ?? null,
    ready: errors.length === 0 && blockers.length === 0,
    errors,
    blockers,
    evidence: {
      nodeMatrix: workflow ? workflow.includes("node: [20, 24]") : false,
      postgresConformance: workflow ? workflow.includes("tests/postgres-shared-state-conformance.test.mjs") : false,
      enforcedOciIsolation: workflow ? workflow.includes("tests/oci-scanner-sandbox.test.mjs") : false,
      dependencyLockfile: hasNpmLock,
    },
  };
  return result;
}

function renderText(report) {
  const lines = [
    `SynSec release readiness: ${report.ready ? "READY" : "NOT READY"}`,
    `Version: ${report.releaseVersion ?? "unknown"}`,
  ];
  for (const entry of report.errors) lines.push(`ERROR ${entry.code}: ${entry.message}`);
  for (const entry of report.blockers) lines.push(`BLOCKER ${entry.code}: ${entry.message}`);
  return `${lines.join("\n")}\n`;
}

async function main() {
  const args = new Set(process.argv.slice(2));
  const strict = args.has("--strict");
  const json = args.has("--json");
  const report = await assessReleaseReadiness(process.cwd());
  process.stdout.write(json ? `${JSON.stringify(report, null, 2)}\n` : renderText(report));
  if (report.errors.length > 0 || (strict && report.blockers.length > 0)) process.exitCode = 1;
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : undefined;
if (invokedPath === fileURLToPath(import.meta.url)) {
  await main();
}
