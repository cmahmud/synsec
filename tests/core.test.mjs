import assert from "node:assert/strict";
import test from "node:test";
import { correlateFindings } from "../packages/core/dist/index.js";

test("correlates duplicate findings from multiple scanners", () => {
  const base = {
    category: "dependency",
    severity: "high",
    confidence: 0.8,
    location: { path: "package-lock.json" },
    identifiers: { cve: ["CVE-2026-1234"] },
    title: "Example vulnerable dependency",
  };

  const correlated = correlateFindings([
    {
      ...base,
      id: "one",
      scanner: { name: "trivy", ruleId: "CVE-2026-1234" },
    },
    {
      ...base,
      id: "two",
      confidence: 0.95,
      scanner: { name: "grype", ruleId: "CVE-2026-1234" },
    },
  ]);

  assert.equal(correlated.length, 1);
  assert.equal(correlated[0].primary.id, "two");
  assert.equal(correlated[0].duplicates.length, 1);
  assert.equal(correlated[0].sources.length, 2);
});
