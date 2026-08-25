import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assessReleaseReadiness } from "../scripts/release-readiness.mjs";

const workflow = `name: CI
jobs:
  build-and-test:
    strategy:
      matrix:
        node: [20, 24]
    steps:
      - run: npm run build
      - run: npm run typecheck
      - run: npm test
  postgres-shared-state:
    services:
      postgres:
        image: postgres:16-alpine
    steps:
      - run: node --test tests/postgres-shared-state-conformance.test.mjs tests/postgres-hosted-installation-ownership.test.mjs
      - run: node --test tests/oci-scanner-sandbox.test.mjs
`;

async function fixture({ lockfile = false, packageOverrides = {}, workflowText = workflow } = {}) {
  const root = await mkdtemp(join(tmpdir(), "synsec-release-readiness-"));
  await mkdir(join(root, ".github/workflows"), { recursive: true });
  await mkdir(join(root, "docs"), { recursive: true });
  await writeFile(join(root, "package.json"), JSON.stringify({
    name: "synsec",
    version: "0.2.0",
    private: true,
    engines: { node: ">=20" },
    ...packageOverrides,
  }));
  await writeFile(join(root, ".github/workflows/ci.yml"), workflowText);
  for (const name of [
    "GITHUB_APP_UPGRADES.md",
    "GITHUB_APP_SERVICE_MAINTENANCE.md",
    "HOSTED_INSTALLATION_OWNERSHIP.md",
    "HOSTED_INSTALLATION_REVERIFICATION_SWEEPS.md",
  ]) await writeFile(join(root, "docs", name), "# fixture\n");
  if (lockfile) await writeFile(join(root, "package-lock.json"), "{}\n");
  return root;
}

test("release readiness reports missing lockfile as an explicit blocker rather than fabricated readiness", async () => {
  const root = await fixture();
  const report = await assessReleaseReadiness(root);
  assert.equal(report.ready, false);
  assert.deepEqual(report.errors, []);
  assert.deepEqual(report.blockers.map(({ code }) => code), ["dependency-lockfile-missing"]);
  assert.equal(report.evidence.dependencyLockfile, false);
});

test("release readiness treats malformed release invariants as hard errors", async () => {
  const root = await fixture({
    packageOverrides: { version: "next", private: false, engines: { node: ">=18" } },
  });
  const report = await assessReleaseReadiness(root);
  assert.equal(report.ready, false);
  assert.deepEqual(new Set(report.errors.map(({ code }) => code)), new Set([
    "package-version-invalid",
    "node-engine-policy-mismatch",
    "root-package-publishable",
  ]));
});

test("release readiness rejects CI that drops real backend or sandbox validation", async () => {
  const root = await fixture({ workflowText: "jobs:\n  build: npm test\n" });
  const report = await assessReleaseReadiness(root);
  assert.equal(report.ready, false);
  assert.ok(report.errors.some(({ code }) => code === "ci-coverage-incomplete"));
  assert.equal(report.evidence.postgresConformance, false);
  assert.equal(report.evidence.enforcedOciIsolation, false);
});

test("committed lockfile still blocks readiness until CI enforces npm ci", async () => {
  const root = await fixture({ lockfile: true });
  const report = await assessReleaseReadiness(root);
  assert.equal(report.ready, false);
  assert.deepEqual(report.errors, []);
  assert.deepEqual(report.blockers.map(({ code }) => code), ["ci-not-using-lockfile"]);
});

test("release readiness becomes ready only with lockfile and lockfile-enforced CI", async () => {
  const root = await fixture({ lockfile: true, workflowText: `${workflow}\n# npm ci\n` });
  const report = await assessReleaseReadiness(root);
  assert.equal(report.ready, true);
  assert.deepEqual(report.errors, []);
  assert.deepEqual(report.blockers, []);
  assert.equal(report.evidence.nodeMatrix, true);
  assert.equal(report.evidence.postgresConformance, true);
  assert.equal(report.evidence.enforcedOciIsolation, true);
  assert.equal(report.evidence.dependencyLockfile, true);
});
