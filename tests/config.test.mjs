import test from "node:test";
import assert from "node:assert/strict";
import { defaultConfig, parseConfig, resolveAiModel } from "../packages/config/dist/index.js";

test("default config prefers the maintained scanner set and keeps AI off", () => {
  assert.equal(defaultConfig.ai.enabled, false);
  assert.equal(defaultConfig.ai.sendSourceContext, false);
  assert.ok(defaultConfig.scanners.includes("betterleaks"));
  assert.ok(defaultConfig.scanners.includes("opengrep"));
  assert.equal(defaultConfig.reports.markdown, ".synsec/report.md");
});

test("parseConfig merges user values with safe defaults", () => {
  const config = parseConfig({
    schemaVersion: 1,
    scanners: ["trivy"],
    parallelism: 2,
    failOn: "high",
    reports: { markdown: "security.md" },
    ai: {
      enabled: true,
      sendSourceContext: false,
      baseUrl: "http://localhost:8080/v1",
      model: "router/default",
      workflowModels: {
        "dependency-review": "router/dependency",
        "secrets-review": "router/secrets",
        ignored: 42,
      },
    },
  });
  assert.deepEqual(config.scanners, ["trivy"]);
  assert.equal(config.parallelism, 2);
  assert.equal(config.failOn, "high");
  assert.equal(config.ai.enabled, true);
  assert.equal(config.ai.sendSourceContext, false);
  assert.equal(config.reports.json, ".synsec/report.json");
  assert.equal(config.reports.markdown, "security.md");
  assert.equal(config.ai.workflowModels["dependency-review"], "router/dependency");
  assert.equal(config.ai.workflowModels.ignored, undefined);
});

test("AI model routing prefers explicit override, then workflow route, then configured and environment defaults", () => {
  const config = parseConfig({
    ai: {
      enabled: true,
      model: "router/default",
      workflowModels: { "dependency-review": "router/dependency" },
    },
  }).ai;

  assert.equal(resolveAiModel(config, {
    workflowId: "dependency-review",
    overrideModel: "router/forced",
    environmentModel: "router/env",
  }), "router/forced");
  assert.equal(resolveAiModel(config, {
    workflowId: "dependency-review",
    environmentModel: "router/env",
  }), "router/dependency");
  assert.equal(resolveAiModel(config, {
    workflowId: "repository-review",
    environmentModel: "router/env",
  }), "router/default");
  assert.equal(resolveAiModel({ ...defaultConfig.ai }, {
    workflowId: "repository-review",
    environmentModel: "router/env",
  }), "router/env");
});
