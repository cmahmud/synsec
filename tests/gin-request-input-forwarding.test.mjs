import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { findingGinRequestInputForwardingEvidence } from "@synsec/repository/gin-request-input-forwarding";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function makeRepository(files) {
  const root = await mkdtemp(join(tmpdir(), "synsec-gin-request-forwarding-"));
  const inputs = [];
  for (const [path, content] of Object.entries(files)) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), content, "utf8");
    inputs.push({ path, size: Buffer.byteLength(content) });
  }
  return { root, files: inputs, cleanup: () => rm(root, { recursive: true, force: true }) };
}

async function analyze(repo, options = {}) {
  const index = await buildRepositoryIndex(repo.root, repo.files);
  return buildRepositoryRouteFlowAnalysis(
    repo.root,
    repo.files,
    index,
    buildModuleGraph(index, repo.files),
    options,
  );
}

function sourceWithHandler(handlerLines) {
  return [
    "package api",
    'import "github.com/gin-gonic/gin"',
    "func runJob(c *gin.Context) {",
    ...handlerLines,
    "}",
    "func runQuery(term string) {",
    '  db.Query("select 1")',
    "}",
    "func routes() {",
    "  router := gin.Default()",
    '  router.GET("/jobs", runJob)',
    "}",
  ].join("\n");
}

test("aggregate Gin flow carries one unchanged single-use local request value to an exact callee sink", async () => {
  const repo = await makeRepository({
    "api/routes.go": sourceWithHandler([
      '  term := c.Query("q")',
      "  runQuery(term)",
    ]),
  });
  try {
    const analysis = await analyze(repo);
    assert.deepEqual(analysis.ginRequestInputForwardingFlows.map((context) => ({
      route: context.route.route,
      sourceKinds: context.sourceKinds,
      sinkKinds: context.sinkKinds,
      interpretation: context.interpretation,
      evidence: context.evidence.map((item) => ({
        sourceLine: item.source.line,
        useLine: item.binding.useLine,
        sinkLine: item.sink.line,
        distance: item.callDistance,
      })),
    })), [{
      route: "/jobs",
      sourceKinds: ["query"],
      sinkKinds: ["database"],
      interpretation: "structural-gin-context-source-single-use-local-call-sink-evidence-only",
      evidence: [{ sourceLine: 4, useLine: 5, sinkLine: 8, distance: 1 }],
    }]);
    assert.deepEqual(findingGinRequestInputForwardingEvidence(
      analysis.ginRequestInputForwardingFlows,
      "api/routes.go",
      8,
    ), [{
      method: "GET",
      route: "/jobs",
      frameworkHint: "Gin router",
      handler: "runJob",
      sourceKind: "query",
      sourceFunction: "runJob",
      sinkKind: "database",
      sinkFunction: "runQuery",
      callDistance: 1,
      bindingHops: 1,
      interpretation: "structural-gin-context-source-single-use-local-call-sink-evidence-only",
    }]);
    assert.equal(JSON.stringify(analysis.ginRequestInputForwardingFlows).includes('"q"'), false);
  } finally {
    await repo.cleanup();
  }
});

test("Gin local forwarding fails closed on multiple use, reassignment, and transformation", async () => {
  const cases = {
    multiple: [
      '  term := c.Query("q")',
      "  log.Print(term)",
      "  runQuery(term)",
    ],
    reassigned: [
      '  term := c.Query("q")',
      '  term = "fixed"',
      "  runQuery(term)",
    ],
    transformed: [
      '  term := c.Query("q")',
      "  runQuery(strings.TrimSpace(term))",
    ],
  };
  for (const [name, handlerLines] of Object.entries(cases)) {
    const repo = await makeRepository({ [`api/${name}.go`]: sourceWithHandler(handlerLines) });
    try {
      const analysis = await analyze(repo);
      assert.deepEqual(analysis.ginRequestInputForwardingFlows, [], name);
    } finally {
      await repo.cleanup();
    }
  }
});

test("Gin local forwarding honors its independent forward-line bound", async () => {
  const repo = await makeRepository({
    "api/routes.go": sourceWithHandler([
      '  term := c.Param("job_id")',
      "",
      "  runQuery(term)",
    ]),
  });
  try {
    const tight = await analyze(repo, { maxGinRequestInputForwardLines: 1 });
    assert.deepEqual(tight.ginRequestInputForwardingFlows, []);
    const allowed = await analyze(repo, { maxGinRequestInputForwardLines: 2 });
    assert.equal(allowed.ginRequestInputForwardingFlows[0]?.sourceKinds[0], "path");
  } finally {
    await repo.cleanup();
  }
});
