import test from "node:test";
import assert from "node:assert/strict";
import { parseSarifJson } from "../packages/scanners/dist/index.js";

function sarif(uri) {
  return JSON.stringify({
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "Fixture" } },
      results: [{
        ruleId: "FIX-1",
        level: "warning",
        message: { text: "Fixture" },
        locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 3 } } }],
      }],
    }],
  });
}

test("SARIF import converts file URIs inside the repository to relative paths", () => {
  const findings = parseSarifJson(sarif("file:///repo/src/app.ts"), undefined, "/repo");
  assert.equal(findings[0].location.path, "src/app.ts");
});

test("SARIF import drops absolute paths outside the repository and non-file URLs", () => {
  const outside = parseSarifJson(sarif("file:///etc/passwd"), undefined, "/repo");
  assert.equal(outside[0].location, undefined);
  const remote = parseSarifJson(sarif("https://example.invalid/source.ts"), undefined, "/repo");
  assert.equal(remote[0].location, undefined);
});
