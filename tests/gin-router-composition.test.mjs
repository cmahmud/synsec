import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildCallGraph } from "@synsec/repository/call-graph";
import { composeGinRouterEntrypoints } from "@synsec/repository/gin-router-composition";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function makeRepository(files) {
  const root = await mkdtemp(join(tmpdir(), "synsec-gin-router-"));
  const inputs = [];
  for (const [path, content] of Object.entries(files)) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), content, "utf8");
    inputs.push({ path, size: Buffer.byteLength(content) });
  }
  return {
    root,
    files: inputs,
    cleanup: () => rm(root, { recursive: true, force: true }),
  };
}

test("Gin groups, middleware, Go calls, and same-file handlers participate in exact sink correlation", async () => {
  const source = [
    "package api",
    "",
    "import (",
    '  "github.com/gin-gonic/gin"',
    ")",
    "",
    "func requireUser(c *gin.Context) {}",
    "func audit(c *gin.Context) {}",
    "func runJob(c *gin.Context) {",
    "  runQuery()",
    "}",
    "func runQuery() {",
    '  db.Query("select 1")',
    "}",
    "func routes() {",
    "  router := gin.Default()",
    '  api := router.Group("/api", requireUser)',
    '  jobs := api.Group("/jobs")',
    '  jobs.POST("/run", audit, runJob)',
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

    const goNodes = analysis.callGraph.nodes.filter((node) => node.kind === "go-function");
    assert.deepEqual(goNodes.map((node) => node.name), ["requireUser", "audit", "runJob", "runQuery", "routes"]);
    assert.equal(analysis.callGraph.edges.some((edge) => edge.callee === "runQuery" && edge.resolution === "same-file-function"), true);

    const entrypoint = analysis.entrypoints.find((item) => item.route.route === "/api/jobs/run");
    assert.equal(entrypoint?.route.method, "POST");
    assert.equal(entrypoint?.route.frameworkHint, "Gin router");
    assert.equal(entrypoint?.handler?.name, "runJob");
    assert.equal(entrypoint?.resolution, "named-function");

    const middleware = analysis.ginMiddlewareContexts.find((item) => item.route.route === "/api/jobs/run");
    assert.deepEqual(middleware?.middleware, [
      { name: "requireUser", source: "group", line: 18 },
      { name: "audit", source: "route", line: 20 },
    ]);
    assert.equal(middleware?.scope.depth, 2);
    assert.equal(middleware?.interpretation, "structural-gin-route-middleware-attachment-not-runtime-protection");

    const flow = analysis.routeFlows.find((item) => item.route.route === "/api/jobs/run");
    assert.deepEqual(flow?.evidence
      .filter((item) => item.kind === "database")
      .map((item) => ({ path: item.path, line: item.line, depth: item.depth, functionName: item.functionName })), [
      { path: "api/routes.go", line: 13, depth: 1, functionName: "runQuery" },
    ]);
    assert.equal(flow?.interpretation, "structural-route-call-sink-evidence-only");
  } finally {
    await repo.cleanup();
  }
});

test("Gin routes resolve one unique handler in the same Go package directory", async () => {
  const routes = [
    "package api",
    'import "github.com/gin-gonic/gin"',
    "func routes() {",
    "  router := gin.New()",
    '  router.POST("/jobs/run", runJob)',
    "}",
  ].join("\n");
  const handlers = [
    "package api",
    'import "github.com/gin-gonic/gin"',
    "func runJob(c *gin.Context) {",
    '  db.Query("select 1")',
    "}",
  ].join("\n");
  const repo = await makeRepository({ "api/routes.go": routes, "api/handlers.go": handlers });
  try {
    const index = await buildRepositoryIndex(repo.root, repo.files);
    const analysis = await buildRepositoryRouteFlowAnalysis(
      repo.root,
      repo.files,
      index,
      buildModuleGraph(index, repo.files),
    );
    const entrypoint = analysis.entrypoints.find((item) => item.route.route === "/jobs/run");
    assert.equal(entrypoint?.handler?.path, "api/handlers.go");
    assert.equal(entrypoint?.handler?.name, "runJob");
    const flow = analysis.routeFlows.find((item) => item.route.route === "/jobs/run");
    assert.deepEqual(flow?.evidence.map((item) => ({ path: item.path, line: item.line, kind: item.kind })), [
      { path: "api/handlers.go", line: 4, kind: "database" },
    ]);
  } finally {
    await repo.cleanup();
  }
});

test("Gin composition fails closed on dynamic group prefixes", async () => {
  const source = [
    "package api",
    'import "github.com/gin-gonic/gin"',
    "func status(c *gin.Context) {}",
    "func routes() {",
    "  router := gin.Default()",
    "  api := router.Group(apiPrefix)",
    '  api.GET("/status", status)',
    "}",
  ].join("\n");
  const repo = await makeRepository({ "routes.go": source });
  try {
    const graph = await buildCallGraph(repo.root, repo.files);
    const result = await composeGinRouterEntrypoints(repo.root, repo.files, graph, []);
    assert.deepEqual(result.entrypoints, []);
    assert.deepEqual(result.middlewareContexts, []);
  } finally {
    await repo.cleanup();
  }
});

test("Gin composition rejects aliased imports and transformed handlers", async () => {
  const source = [
    "package api",
    'import g "github.com/gin-gonic/gin"',
    "func status(c *g.Context) {}",
    "func routes() {",
    "  router := g.Default()",
    '  router.GET("/status", wrap(status))',
    "}",
  ].join("\n");
  const repo = await makeRepository({ "routes.go": source });
  try {
    const graph = await buildCallGraph(repo.root, repo.files);
    const result = await composeGinRouterEntrypoints(repo.root, repo.files, graph, []);
    assert.deepEqual(result.entrypoints, []);
  } finally {
    await repo.cleanup();
  }
});

test("Gin composition rejects reassigned scopes and ambiguous same-package handlers", async () => {
  const routes = [
    "package api",
    'import "github.com/gin-gonic/gin"',
    "func runJob(c *gin.Context) {}",
    "func routes() {",
    "  router := gin.Default()",
    "  router = replacement",
    '  router.POST("/jobs/run", runJob)',
    "}",
  ].join("\n");
  const duplicate = [
    "package api",
    'import "github.com/gin-gonic/gin"',
    "func runJob(c *gin.Context) {}",
  ].join("\n");
  const repo = await makeRepository({ "api/routes.go": routes, "api/duplicate.go": duplicate });
  try {
    const graph = await buildCallGraph(repo.root, repo.files);
    const result = await composeGinRouterEntrypoints(repo.root, repo.files, graph, []);
    assert.deepEqual(result.entrypoints, []);
  } finally {
    await repo.cleanup();
  }
});

test("Gin composition validates route output bounds", async () => {
  const source = [
    "package api",
    'import "github.com/gin-gonic/gin"',
    "func status(c *gin.Context) {}",
    "func routes() {",
    "  router := gin.Default()",
    '  router.GET("/status", status)',
    "}",
  ].join("\n");
  const repo = await makeRepository({ "routes.go": source });
  try {
    const graph = await buildCallGraph(repo.root, repo.files);
    await assert.rejects(
      composeGinRouterEntrypoints(repo.root, repo.files, graph, [], { maxRoutes: 0 }),
      /Gin maxRoutes must be an integer between 1 and 10000/,
    );
  } finally {
    await repo.cleanup();
  }
});
