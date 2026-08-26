import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function makeRepository(files) {
  const root = await mkdtemp(join(tmpdir(), "synsec-gin-request-flow-aggregate-"));
  const inputs = [];
  for (const [path, content] of Object.entries(files)) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), content, "utf8");
    inputs.push({ path, size: Buffer.byteLength(content) });
  }
  return { root, files: inputs, cleanup: () => rm(root, { recursive: true, force: true }) };
}

test("aggregate repository route-flow analysis includes bounded Gin direct request-source evidence", async () => {
  const source = [
    "package api",
    'import "github.com/gin-gonic/gin"',
    "func runJob(c *gin.Context) {",
    '  runQuery(c.GetHeader("X-Trace"))',
    "}",
    "func runQuery(term string) {",
    '  db.Query("select 1")',
    "}",
    "func routes() {",
    "  router := gin.Default()",
    '  router.POST("/jobs", runJob)',
    "}",
  ].join("\n");
  const repo = await makeRepository({ "api/routes.go": source });
  try {
    const index = await buildRepositoryIndex(repo.root, repo.files);
    const analysis = await buildRepositoryRouteFlowAnalysis(
      repo.root,
      repo.files,
      index,
      buildModuleGraph(index, repo.files),
    );

    assert.deepEqual(analysis.ginRequestInputFlows.map((context) => ({
      route: context.route.route,
      frameworkHint: context.route.frameworkHint,
      handler: context.handler.name,
      sourceKinds: context.sourceKinds,
      sinkKinds: context.sinkKinds,
      interpretation: context.interpretation,
      evidence: context.evidence.map((item) => ({
        sourceKind: item.source.kind,
        sourceLine: item.source.line,
        sinkKind: item.sink.kind,
        sinkLine: item.sink.line,
        callDistance: item.callDistance,
      })),
    })), [{
      route: "/jobs",
      frameworkHint: "Gin router",
      handler: "runJob",
      sourceKinds: ["header"],
      sinkKinds: ["database"],
      interpretation: "structural-gin-context-source-direct-call-sink-evidence-only",
      evidence: [{
        sourceKind: "header",
        sourceLine: 4,
        sinkKind: "database",
        sinkLine: 7,
        callDistance: 1,
      }],
    }]);
    assert.equal(JSON.stringify(analysis.ginRequestInputFlows).includes("X-Trace"), false);
  } finally {
    await repo.cleanup();
  }
});
