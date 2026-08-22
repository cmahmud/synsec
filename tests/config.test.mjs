import test from "node:test";
import assert from "node:assert/strict";
import { defaultConfig, parseConfig } from "../packages/config/dist/index.js";

test("default config prefers the maintained scanner set and keeps AI off", () => {
  assert.equal(defaultConfig.ai.enabled, false);
  assert.equal(defaultConfig.ai.sendSourceContext, false);
  assert.ok(defaultConfig.scanners.includes("betterleaks"));
  assert.ok(defaultConfig.scanners.includes("opengrep"));
});

test("parseConfig merges user values with safe defaults", () => {
  const config = parseConfig({
    schemaVersion: 1,
    scanners: ["trivy"],
    parallelism: 2,
    failOn: "high",
    ai: { enabled: true, sendSourceContext: false, baseUrl: "http://localhost:8080/v1", model: "router/model" },
  });
  assert.deepEqual(config.scanners, ["trivy"]);
  assert.equal(config.parallelism, 2);
  assert.equal(config.failOn, "high");
  assert.equal(config.ai.enabled, true);
  assert.equal(config.ai.sendSourceContext, false);
  assert.equal(config.reports.json, ".synsec/report.json");
});
