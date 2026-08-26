import assert from "node:assert/strict";
import test from "node:test";

import { findingCoverageContext, parseLcovCoverage } from "@synsec/repository/coverage-context";

function finding(path, line) {
  return {
    id: "fixture",
    title: "Fixture",
    category: "sast",
    severity: "medium",
    confidence: 1,
    scanner: { name: "fixture" },
    location: { path, startLine: line },
  };
}

test("LCOV coverage maps observed test hits to finding lines without claiming runtime reachability", () => {
  const coverage = parseLcovCoverage([
    "TN:",
    "SF:src/a.ts",
    "DA:10,3",
    "DA:11,0",
    "end_of_record",
    "SF:src/b.ts",
    "DA:2,1",
    "end_of_record",
    "",
  ].join("\n"));

  assert.equal(coverage.fileCount, 2);
  assert.equal(coverage.lineCount, 3);
  assert.equal(coverage.interpretation, "observed-test-coverage-not-runtime-reachability");
  assert.deepEqual(findingCoverageContext(coverage, finding("src/a.ts", 10)), {
    path: "src/a.ts",
    line: 10,
    status: "executed",
    hits: 3,
    interpretation: "observed-test-coverage-not-runtime-reachability",
  });
  assert.equal(findingCoverageContext(coverage, finding("src/a.ts", 11)).status, "not-executed");
  assert.equal(findingCoverageContext(coverage, finding("src/a.ts", 12)).status, "no-data");
});

test("LCOV parsing combines duplicate line records deterministically", () => {
  const coverage = parseLcovCoverage("SF:src/a.ts\nDA:10,2\nDA:10,5\nend_of_record\n");
  assert.equal(coverage.lineCount, 1);
  assert.deepEqual(coverage.files[0].lines, [{ line: 10, hits: 7 }]);
});

test("LCOV absolute paths are accepted only inside an explicitly bounded repository root", () => {
  const root = process.platform === "win32" ? "C:\\repo" : "/repo";
  const inside = process.platform === "win32" ? "C:\\repo\\src\\a.ts" : "/repo/src/a.ts";
  const outside = process.platform === "win32" ? "C:\\other\\secret.ts" : "/other/secret.ts";

  const withoutRoot = parseLcovCoverage(`SF:${inside}\nDA:1,1\nend_of_record\n`);
  assert.equal(withoutRoot.fileCount, 0);

  const withRoot = parseLcovCoverage([
    `SF:${inside}`,
    "DA:1,1",
    "end_of_record",
    `SF:${outside}`,
    "DA:2,1",
    "end_of_record",
  ].join("\n"), { repositoryRoot: root });
  assert.equal(withRoot.fileCount, 1);
  assert.equal(withRoot.files[0].path, "src/a.ts");
});

test("LCOV parser ignores path traversal records and rejects malformed numeric data", () => {
  const traversal = parseLcovCoverage("SF:../outside.ts\nDA:1,1\nend_of_record\n");
  assert.equal(traversal.fileCount, 0);

  assert.throws(() => parseLcovCoverage("SF:src/a.ts\nDA:not-a-line,1\nend_of_record\n"), /line number/);
  assert.throws(() => parseLcovCoverage("SF:src/a.ts\nDA:1,-1\nend_of_record\n"), /hit count/);
});

test("finding coverage returns no-data when a finding has no concrete covered location", () => {
  const coverage = parseLcovCoverage("SF:src/a.ts\nDA:1,1\nend_of_record\n");
  const result = findingCoverageContext(coverage, {
    id: "repo",
    title: "Repository-level",
    category: "posture",
    severity: "low",
    confidence: 1,
    scanner: { name: "fixture" },
  });
  assert.equal(result.status, "no-data");
});
