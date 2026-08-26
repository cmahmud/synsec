import assert from "node:assert/strict";
import test from "node:test";
import { correlateFindings } from "../packages/core/dist/index.js";

test("correlates the same dependency advisory across scanners despite different rule IDs, titles, and alias sets", () => {
  const correlated = correlateFindings([
    {
      id: "one",
      category: "dependency",
      severity: "high",
      confidence: 0.8,
      location: { path: "package-lock.json" },
      identifiers: { cve: ["CVE-2026-1234"] },
      title: "First scanner advisory title",
      scanner: { name: "trivy", ruleId: "CVE-2026-1234" },
      metadata: { package: "demo-package" },
      fingerprint: "native-trivy-fingerprint",
    },
    {
      id: "two",
      category: "dependency",
      severity: "critical",
      confidence: 0.95,
      location: { path: "package-lock.json" },
      identifiers: { cve: ["CVE-2026-1234"], ghsa: ["GHSA-demo-demo-demo"] },
      title: "Second scanner uses a different title",
      scanner: { name: "grype", ruleId: "GHSA-demo-demo-demo" },
      metadata: { package: "demo-package" },
      fingerprint: "native-grype-fingerprint",
    },
  ]);

  assert.equal(correlated.length, 1);
  assert.equal(correlated[0].primary.id, "two");
  assert.equal(correlated[0].duplicates.length, 1);
  assert.equal(correlated[0].sources.length, 2);
  assert.notEqual(correlated[0].fingerprint, "native-trivy-fingerprint");
});

test("correlates secret scanner findings at the same source location without hashing secret content", () => {
  const correlated = correlateFindings([
    {
      id: "one",
      title: "Potential API token",
      category: "secret",
      severity: "high",
      confidence: 0.9,
      scanner: { name: "trivy", ruleId: "generic-token" },
      location: { path: "src/config.ts", startLine: 7 },
    },
    {
      id: "two",
      title: "Credential detected",
      category: "secret",
      severity: "high",
      confidence: 0.98,
      scanner: { name: "betterleaks", ruleId: "vendor-token" },
      location: { path: "src/config.ts", startLine: 7 },
    },
  ]);

  assert.equal(correlated.length, 1);
  assert.equal(correlated[0].primary.id, "two");
  assert.equal(correlated[0].sources.length, 2);
});
