import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import {
  buildGinRouteRequestInputFlowContexts,
  findingGinRequestInputFlowEvidence,
} from "@synsec/repository/gin-request-input-flow";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function makeRepository(files) {
  const root = await mkdtemp(join(tmpdir(), "synsec-gin-request-flow-"));
  const inputs = [];
  for (const [path, content] of Object.entries(files)) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), content, "utf8");
    inputs.push({ path, size: Buffer.byteLength(content) });
  }
  return { root, files: inputs, cleanup: () => rm(root, { recursive: true, force: true }) };
}

async function analyze(repo) {
  const index = await buildRepositoryIndex(repo.root, repo.files);
  return buildRepositoryRouteFlowAnalysis(
    repo.root,
    repo.files,
    index,
    buildModuleGraph(index, repo.files),
  );
}

test("Gin direct context query passed to a direct callee produces structural source-to-sink evidence", async () => {
  const source = [
    "package api",
    'import "github.com/gin-gonic/gin"',
    "func runJob(c *gin.Context) {",
    '  runQuery(c.Query("q"))',
    "}",
    "func runQuery(term string) {",
    '  db.Query("select 1")',
    "}",
    "func routes() {",
    "  router := gin.Default()",
    '  router.GET("/jobs", runJob)',
    "}",
  ].join("\n");
  const repo = await makeRepository({ "api/routes.go": source });
  try {
    const analysis = await analyze(repo);
    const ginFlow = analysis.routeFlows.find((item) => item.route.route === "/jobs" && item.route.frameworkHint === "Gin router");
    assert.equal(ginFlow?.handler.name, "runJob");
    assert.deepEqual(ginFlow?.evidence.filter((item) => item.kind === "database").map((item) => ({
      line: item.line,
      functionName: item.functionName,
      depth: item.depth,
    })), [{ line: 7, functionName: "runQuery", depth: 1 }]);
    assert.equal(analysis.callGraph.edges.some((edge) =>
      edge.line === 4 && edge.callee === "runQuery" && edge.resolution === "same-file-function"), true);
    assert.deepEqual(analysis.callGraph.nodes.filter((node) => node.kind === "go-function").map((node) => ({
      name: node.name,
      line: node.line,
      endLine: node.endLine,
    })), [
      { name: "runJob", line: 3, endLine: 5 },
      { name: "runQuery", line: 6, endLine: 8 },
      { name: "routes", line: 9, endLine: 12 },
    ]);

    const contexts = await buildGinRouteRequestInputFlowContexts(repo.root, analysis.routeFlows, analysis.callGraph);
    assert.equal(contexts.length, 1);
    const context = contexts[0];
    assert.equal(context?.route.route, "/jobs");
    assert.equal(context?.route.frameworkHint, "Gin router");
    assert.equal(context?.interpretation, "structural-gin-context-source-direct-call-sink-evidence-only");
    assert.deepEqual(context?.sourceKinds, ["query"]);
    assert.deepEqual(context?.evidence.map((item) => ({
      sourceLine: item.source.line,
      sourceKind: item.source.kind,
      access: item.source.access,
      sinkLine: item.sink.line,
      sinkKind: item.sink.kind,
      sinkFunction: item.sink.functionName,
      callDistance: item.callDistance,
    })), [{
      sourceLine: 4,
      sourceKind: "query",
      access: "gin.Context.Query",
      sinkLine: 7,
      sinkKind: "database",
      sinkFunction: "runQuery",
      callDistance: 1,
    }]);
    assert.deepEqual(findingGinRequestInputFlowEvidence(contexts, "api/routes.go", 7), [{
      method: "GET",
      route: "/jobs",
      frameworkHint: "Gin router",
      handler: "runJob",
      sourceKind: "query",
      sourceFunction: "runJob",
      sinkKind: "database",
      sinkFunction: "runQuery",
      callDistance: 1,
      interpretation: "structural-gin-context-source-direct-call-sink-evidence-only",
    }]);
    assert.equal(JSON.stringify(context).includes('"q"'), false);
  } finally {
    await repo.cleanup();
  }
});

test("Gin direct context access on the exact sink line has zero call distance", async () => {
  const source = [
    "package api",
    'import "github.com/gin-gonic/gin"',
    "func runJob(c *gin.Context) {",
    '  db.Query(c.Param("job_id"))',
    "}",
    "func routes() {",
    "  router := gin.Default()",
    '  router.GET("/jobs/:job_id", runJob)',
    "}",
  ].join("\n");
  const repo = await makeRepository({ "api/routes.go": source });
  try {
    const analysis = await analyze(repo);
    const ginFlow = analysis.routeFlows.find((item) => item.route.route === "/jobs/:job_id" && item.route.frameworkHint === "Gin router");
    assert.equal(ginFlow?.handler.name, "runJob");
    assert.deepEqual(ginFlow?.evidence.filter((item) => item.kind === "database").map((item) => ({ line: item.line, functionName: item.functionName })), [
      { line: 4, functionName: "runJob" },
    ]);
    const contexts = await buildGinRouteRequestInputFlowContexts(repo.root, analysis.routeFlows, analysis.callGraph);
    assert.deepEqual(contexts[0]?.evidence.map((item) => ({ kind: item.source.kind, distance: item.callDistance })), [
      { kind: "path", distance: 0 },
    ]);
  } finally {
    await repo.cleanup();
  }
});

test("Gin bound-object APIs and stored request values are not promoted into directional flow", async () => {
  const source = [
    "package api",
    'import "github.com/gin-gonic/gin"',
    "type payload struct { Name string }",
    "func runJob(c *gin.Context) {",
    "  var body payload",
    "  c.ShouldBindJSON(&body)",
    '  term := c.Query("q")',
    "  runQuery(term)",
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
    const analysis = await analyze(repo);
    const contexts = await buildGinRouteRequestInputFlowContexts(repo.root, analysis.routeFlows, analysis.callGraph);
    assert.deepEqual(contexts, []);
  } finally {
    await repo.cleanup();
  }
});

test("Gin request flow fails closed for aliased imports and non-Gin context-looking methods", async () => {
  const aliased = [
    "package api",
    'import g "github.com/gin-gonic/gin"',
    "func runJob(c *g.Context) {",
    '  db.Query(c.Query("q"))',
    "}",
  ].join("\n");
  const lookalike = [
    "package api",
    "type Context struct{}",
    "func runJob(c *Context) {",
    '  db.Query(c.Query("q"))',
    "}",
  ].join("\n");
  for (const [name, source] of [["aliased", aliased], ["lookalike", lookalike]]) {
    const repo = await makeRepository({ [`${name}.go`]: source });
    try {
      const analysis = await analyze(repo);
      const contexts = await buildGinRouteRequestInputFlowContexts(repo.root, analysis.routeFlows, analysis.callGraph);
      assert.deepEqual(contexts, [], name);
    } finally {
      await repo.cleanup();
    }
  }
});

test("Gin request-flow validates resource bounds", async () => {
  const repo = await makeRepository({
    "api/routes.go": [
      "package api",
      'import "github.com/gin-gonic/gin"',
      "func runJob(c *gin.Context) {}",
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    await assert.rejects(
      buildGinRouteRequestInputFlowContexts(repo.root, analysis.routeFlows, analysis.callGraph, { maxEvidence: 0 }),
      /Gin request-flow maxEvidence must be an integer between 1 and 50/,
    );
  } finally {
    await repo.cleanup();
  }
});
