import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { findingKoaRequestInputFlowEvidence } from "@synsec/repository/koa-request-input-flow";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function makeRepository(files) {
  const root = await mkdtemp(join(tmpdir(), "synsec-koa-request-flow-"));
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

async function analyze(repo) {
  const index = await buildRepositoryIndex(repo.root, repo.files);
  return buildRepositoryRouteFlowAnalysis(
    repo.root,
    repo.files,
    index,
    buildModuleGraph(index, repo.files),
  );
}

test("Koa direct context access on a call line produces bounded source-to-sink evidence", async () => {
  const source = [
    'import Router from "@koa/router";',
    'const router = new Router({ prefix: "/api" });',
    "function runJob(ctx) {",
    "  execute(ctx.request.body.command);",
    "}",
    "function execute(command) {",
    "  child_process.exec(command);",
    "}",
    'router.post("/jobs/run", runJob);',
  ].join("\n");
  const repo = await makeRepository({ "routes.ts": source });
  try {
    const analysis = await analyze(repo);
    const entrypoint = analysis.entrypoints.find((item) => item.route.route === "/api/jobs/run" && item.route.frameworkHint === "Koa router");
    assert.equal(entrypoint?.resolution, "named-function");

    const flow = analysis.koaRequestInputFlows.find((item) => item.route.route === "/api/jobs/run");
    assert.equal(flow?.interpretation, "structural-koa-context-source-direct-call-sink-evidence-only");
    assert.deepEqual(flow?.evidence.map((item) => ({
      sourceKind: item.source.kind,
      sourceAccess: item.source.access,
      sourceLine: item.source.line,
      sinkKind: item.sink.kind,
      sinkLine: item.sink.line,
      callDistance: item.callDistance,
    })), [{
      sourceKind: "body",
      sourceAccess: "koa.Context.request.body",
      sourceLine: 4,
      sinkKind: "process",
      sinkLine: 7,
      callDistance: 1,
    }]);

    assert.deepEqual(findingKoaRequestInputFlowEvidence(analysis.koaRequestInputFlows, "routes.ts", 7), [{
      method: "POST",
      route: "/api/jobs/run",
      frameworkHint: "Koa router",
      handler: "runJob",
      sourceKind: "body",
      sourceFunction: "runJob",
      sinkKind: "process",
      sinkFunction: "execute",
      callDistance: 1,
      interpretation: "structural-koa-context-source-direct-call-sink-evidence-only",
    }]);
  } finally {
    await repo.cleanup();
  }
});

test("Koa same-line context query and header access correlate only to the exact sink line", async () => {
  const source = [
    'import Router from "@koa/router";',
    "const router = new Router();",
    "function search(ctx) {",
    "  db.execute(ctx.query.term);",
    "  fetch(ctx.get(\"x-upstream\"));",
    "}",
    'router.get("/search", search);',
  ].join("\n");
  const repo = await makeRepository({ "routes.ts": source });
  try {
    const analysis = await analyze(repo);
    const flow = analysis.koaRequestInputFlows.find((item) => item.route.route === "/search");
    assert.deepEqual(flow?.evidence.map((item) => [item.source.kind, item.sink.kind, item.sink.line, item.callDistance]), [
      ["query", "database", 4, 0],
      ["header", "network", 5, 0],
    ]);
  } finally {
    await repo.cleanup();
  }
});

test("Koa imported handlers retain framework identity and direct request-flow evidence", async () => {
  const routes = [
    'import Router from "@koa/router";',
    'import { runJob } from "./handlers.js";',
    "const router = new Router();",
    'router.post("/run", runJob);',
  ].join("\n");
  const handlers = [
    "export function runJob(ctx) {",
    "  child_process.exec(ctx.params.command);",
    "}",
  ].join("\n");
  const repo = await makeRepository({ "routes.ts": routes, "handlers.ts": handlers });
  try {
    const analysis = await analyze(repo);
    const flow = analysis.koaRequestInputFlows.find((item) => item.route.route === "/run");
    assert.equal(flow?.resolution, "imported-named-function");
    assert.equal(flow?.route.frameworkHint, "Koa router");
    assert.deepEqual(flow?.evidence.map((item) => [item.source.kind, item.source.path, item.sink.path, item.callDistance]), [
      ["path", "handlers.ts", "handlers.ts", 0],
    ]);
  } finally {
    await repo.cleanup();
  }
});

test("Koa request flow fails closed on locals and wider forwarding", async () => {
  const source = [
    'import Router from "@koa/router";',
    "const router = new Router();",
    "function runJob(ctx) {",
    "  const command = ctx.query.command;",
    "  execute(command);",
    "}",
    "function execute(command) {",
    "  child_process.exec(command);",
    "}",
    'router.post("/run", runJob);',
  ].join("\n");
  const repo = await makeRepository({ "routes.ts": source });
  try {
    const analysis = await analyze(repo);
    assert.deepEqual(analysis.koaRequestInputFlows, []);
  } finally {
    await repo.cleanup();
  }
});

test("Koa response body is not promoted into request-source evidence", async () => {
  const source = [
    'import Router from "@koa/router";',
    "const router = new Router();",
    "function render(ctx) {",
    "  child_process.exec(ctx.body.command);",
    "}",
    'router.get("/render", render);',
  ].join("\n");
  const repo = await makeRepository({ "routes.ts": source });
  try {
    const analysis = await analyze(repo);
    assert.equal(analysis.routeFlows.some((item) => item.route.route === "/render"), true);
    assert.deepEqual(analysis.koaRequestInputFlows, []);
  } finally {
    await repo.cleanup();
  }
});

test("Koa request flow does not promote generic Node routes with ctx-looking parameters", async () => {
  const source = [
    "function search(ctx) {",
    "  child_process.exec(ctx.query.command);",
    "}",
    'router.get("/search", search);',
  ].join("\n");
  const repo = await makeRepository({ "routes.ts": source });
  try {
    const analysis = await analyze(repo);
    assert.equal(analysis.entrypoints.some((item) => item.route.route === "/search"), true);
    assert.deepEqual(analysis.koaRequestInputFlows, []);
  } finally {
    await repo.cleanup();
  }
});

test("Koa request flow validates evidence bounds", async () => {
  const source = [
    'import Router from "@koa/router";',
    "const router = new Router();",
    "function search(ctx) { child_process.exec(ctx.query.command); }",
    'router.get("/search", search);',
  ].join("\n");
  const repo = await makeRepository({ "routes.ts": source });
  try {
    const index = await buildRepositoryIndex(repo.root, repo.files);
    await assert.rejects(
      buildRepositoryRouteFlowAnalysis(repo.root, repo.files, index, buildModuleGraph(index, repo.files), { maxEvidence: 0 }),
      /maxEvidence must be an integer between 1 and 50/,
    );
  } finally {
    await repo.cleanup();
  }
});
