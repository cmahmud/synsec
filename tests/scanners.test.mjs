import test from "node:test";
import assert from "node:assert/strict";
import {
  parseBetterleaksJson,
  parseCheckovJson,
  parseGrypeJson,
  parseOpengrepJson,
  parseOsvJson,
  parseSarifJson,
  parseScorecardJson,
  parseSyftJson,
} from "../packages/scanners/dist/index.js";

test("Betterleaks parser redacts normalized evidence by design", () => {
  const findings = parseBetterleaksJson(JSON.stringify([{
    RuleID: "github-pat",
    Description: "GitHub token",
    File: "src/config.ts",
    StartLine: 4,
    Fingerprint: "src/config.ts:github-pat:4",
    Secret: "SHOULD_NOT_APPEAR",
    Match: "SHOULD_NOT_APPEAR",
  }]));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, "secret");
  assert.equal(findings[0].evidence, undefined);
  assert.equal(JSON.stringify(findings).includes("SHOULD_NOT_APPEAR"), false);
});

test("Opengrep parser maps code location and severity", () => {
  const findings = parseOpengrepJson(JSON.stringify({
    results: [{
      check_id: "rules.example",
      path: "src/app.ts",
      start: { line: 10, col: 3 },
      end: { line: 10, col: 20 },
      extra: { message: "Unsafe operation", severity: "ERROR", metadata: { cwe: ["CWE-79"] } },
    }],
  }));
  assert.equal(findings[0].severity, "high");
  assert.equal(findings[0].location.startLine, 10);
  assert.deepEqual(findings[0].identifiers.cwe, ["CWE-79"]);
});

test("OSV parser records package vulnerability identifiers", () => {
  const findings = parseOsvJson(JSON.stringify({
    results: [{
      source: { path: "/repo/package-lock.json", type: "lockfile" },
      packages: [{
        package: { name: "demo", version: "1.0.0", ecosystem: "npm" },
        vulnerabilities: [{ id: "GHSA-aaaa-bbbb-cccc", aliases: ["CVE-2026-0001"], summary: "Demo advisory" }],
      }],
    }],
  }), "/repo");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].location.path, "package-lock.json");
  assert.deepEqual(findings[0].identifiers.cve, ["CVE-2026-0001"]);
});

test("Grype parser maps package and fix information", () => {
  const findings = parseGrypeJson(JSON.stringify({
    matches: [{
      vulnerability: { id: "CVE-2026-0002", severity: "High", fix: { versions: ["2.0.0"], state: "fixed" } },
      artifact: { name: "demo", version: "1.0.0", type: "npm", locations: [{ path: "package-lock.json" }] },
    }],
  }));
  assert.equal(findings[0].severity, "high");
  assert.match(findings[0].remediation, /2\.0\.0/);
});

test("Checkov parser maps failed IaC checks", () => {
  const findings = parseCheckovJson(JSON.stringify({
    check_type: "terraform",
    results: { failed_checks: [{ check_id: "CKV_TEST_1", check_name: "Unsafe test resource", file_path: "/main.tf", file_line_range: [1, 4], severity: "HIGH" }] },
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, "iac");
  assert.equal(findings[0].location.path, "main.tf");
});

test("Scorecard parser creates posture findings only for non-perfect checks", () => {
  const findings = parseScorecardJson(JSON.stringify({
    score: 7.2,
    checks: [
      { name: "Branch-Protection", score: 3, reason: "branch protection is incomplete", details: ["detail"], documentation: { short: "Protect important branches", url: "https://example.invalid/docs" } },
      { name: "Security-Policy", score: 10, reason: "security policy found", documentation: { short: "Document security reporting" } },
    ],
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, "repository-posture");
  assert.equal(findings[0].severity, "high");
  assert.equal(findings[0].scanner.ruleId, "Branch-Protection");
});

test("Syft parser normalizes packages, licenses, and repository-relative locations", () => {
  const artifact = parseSyftJson(JSON.stringify({
    descriptor: { name: "syft", version: "1.31.0" },
    source: { id: "source-id", name: "/repo" },
    artifacts: [
      {
        name: "demo-package",
        version: "1.2.3",
        type: "npm",
        purl: "pkg:npm/demo-package@1.2.3",
        licenses: [{ value: "MIT", spdxExpression: "MIT" }],
        locations: [{ path: "/repo/package-lock.json" }],
      },
    ],
  }), "/repo", "2026-08-22T00:00:00.000Z");

  assert.equal(artifact.type, "sbom");
  assert.equal(artifact.packageCount, 1);
  assert.equal(artifact.packages[0].name, "demo-package");
  assert.deepEqual(artifact.packages[0].licenses, ["MIT"]);
  assert.deepEqual(artifact.packages[0].locations, ["package-lock.json"]);
  assert.equal(artifact.metadata.syftVersion, "1.31.0");
});

test("SARIF importer maps tool metadata, severity, identifiers, and location", () => {
  const findings = parseSarifJson(JSON.stringify({
    version: "2.1.0",
    runs: [{
      tool: { driver: {
        name: "ExternalScanner",
        semanticVersion: "3.4.5",
        rules: [{
          id: "EXT-1",
          shortDescription: { text: "External unsafe operation" },
          fullDescription: { text: "Detailed explanation" },
          properties: { identifiers: ["CWE-79"] },
        }],
      } },
      results: [{
        ruleId: "EXT-1",
        ruleIndex: 0,
        level: "error",
        message: { text: "External unsafe operation" },
        locations: [{ physicalLocation: { artifactLocation: { uri: "src/app.ts" }, region: { startLine: 12, startColumn: 2 } } }],
        partialFingerprints: { primaryLocationLineHash: "native-fingerprint" },
        properties: { category: "sast", confidence: 0.91, remediation: "Use the safe API." },
      }],
    }],
  }));

  assert.equal(findings.length, 1);
  assert.equal(findings[0].scanner.name, "ExternalScanner");
  assert.equal(findings[0].severity, "high");
  assert.equal(findings[0].category, "sast");
  assert.equal(findings[0].location.path, "src/app.ts");
  assert.equal(findings[0].location.startLine, 12);
  assert.deepEqual(findings[0].identifiers.cwe, ["CWE-79"]);
  assert.equal(findings[0].fingerprint, "native-fingerprint");
});
