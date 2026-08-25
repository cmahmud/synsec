import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildCallGraph } from "@synsec/repository/call-graph";
import { composeKoaRouterEntrypoints } from "@synsec/repository/koa-router-composition";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function makeRepository(files) {
  const root = await mkdtemp(join(tmpdir(), "synsec-koa-router-"));
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

test("Koa router prefixes, middleware, and same-file handlers participate in exact sink correlation", async () => {
  const source = [
    'import Router from "@koa/router";',
    'const router = new Router({ prefix: "/api" });',
    "function requireUser(ctx, next) { return next(); }",
    "function runJob(ctx) {",
    "  child_process.exec(command);",
    "}",
    'router.post("/jobs/run", requireUser, runJob);',
  ].join("\n");
  const repo = await makeRepository({ "routes.ts": source });
  try {
    const index = await buildRepositoryIndex(repo.root, repo.files);
    const analysis = await buildRepositoryRouteFlowAnalysis(
      repo.root,
      repo.files,
      index,
      buildModuleGraph(index, repo.files),
    );
    const entrypoint = analysis.entrypoints.find((item) => item.route.route === "/api/jobs/run");
    assert.equal(entrypoint?.route.method, "POST");
    assert.equal(entrypoint?.handler?.name, "runJob");
    assert.equal(entrypoint?.resolution, "named-function");

    const middleware = analysis.koaMiddlewareContexts.find((item) => item.route.route === "/api/jobs/run");
    assert.deepEqual(middleware?.middleware, [{ name: "requireUser", line: 7 }]);
    assert.equal(middleware?.interpretation, "structural-koa-route-middleware-attachment-not-runtime-protection");

    const flow = analysis.routeFlows.find((item) => item.route.route === "/api/jobs/run");
    assert.deepEqual(flow?.evidence.map((item) => ({ path: item.path, line: item.line, kind: item.kind, depth: item.depth })), [
      { path: "routes.ts", line: 5, kind: "process", depth: 0 },
    ]);
    assert.equal(flow?.interpretation, "structural-route-call-sink-evidence-only");
  } finally {
    await repo.cleanup();
  }
});

test("Koa routes reuse the repository-local named import resolver for cross-module handlers", async () => {
  const routes = [
    'import Router from "@koa/router";',
    'import { runJob } from "./handlers.js";',
    'const router = new Router({ prefix: "/api" });',
    'router.post("/jobs/run", runJob);',
  ].join("\n");
  const handlers = [
    "export function runJob(ctx) {",
    "  child_process.exec(command);",
    "}",
  ].join("\n");
  const repo = await makeRepository({ "routes.ts": routes, "handlers.ts": handlers });
  try {
    const index = await buildRepositoryIndex(repo.root, repo.files);
    const analysis = await buildRepositoryRouteFlowAnalysis(
      repo.root,
      repo.files,
      index,
      buildModuleGraph(index, repo.files),
    );
    const entrypoint = analysis.entrypoints.find((item) => item.route.route === "/api/jobs/run");
    assert.equal(entrypoint?.resolution, "imported-named-function");
    assert.equal(entrypoint?.handler?.path, "handlers.ts");
    assert.equal(entrypoint?.handler?.name, "runJob");
    const flow = analysis.routeFlows.find((item) => item.route.route === "/api/jobs/run");
    assert.deepEqual(flow?.evidence.map((item) => ({ path: item.path, line: item.line, kind: item.kind })), [
      { path: "handlers.ts", line: 2, kind: "process" },
    ]);
  } finally {
    await repo.cleanup();
  }
});

test("Koa composition fails closed on dynamic prefixes", async () => {
  const source = [
    'import Router from "@koa/router";',
    "const router = new Router({ prefix: API_PREFIX });",
    "function status(ctx) { return true; }",
    'router.get("/status", status);',
  ].join("\n");
  const repo = await makeRepository({ "routes.ts": source });
  try {
    const graph = await buildCallGraph(repo.root, repo.files);
    const result = await composeKoaRouterEntrypoints(repo.root, repo.files, graph, []);
    assert.deepEqual(result.entrypoints, []);
    assert.deepEqual(result.middlewareContexts, []);
  } finally {
    await repo.cleanup();
  }
});

test("Koa composition fails closed on inline or transformed callbacks", async () => {
  const source = [
    'import Router from "@koa/router";',
    "const router = new Router();",
    "function status(ctx) { return true; }",
    'router.get("/inline", async (ctx) => status(ctx));',
    'router.get("/wrapped", wrap(status));',
  ].join("\n");
  const repo = await makeRepository({ "routes.ts": source });
  try {
    const graph = await buildCallGraph(repo.root, repo.files);
    const result = await composeKoaRouterEntrypoints(repo.root, repo.files, graph, []);
    assert.deepEqual(result.entrypoints, []);
    assert.deepEqual(result.middlewareContexts, []);
  } finally {
    await repo.cleanup();
  }
});

test("Koa composition rejects reassigned router bindings", async () => {
  const source = [
    'import Router from "@koa/router";',
    "const router = new Router();",
    "router = replacement;",
    "function status(ctx) { return true; }",
    'router.get("/status", status);',
  ].join("\n");
  const repo = await makeRepository({ "routes.ts": source });
  try {
    const graph = await buildCallGraph(repo.root, repo.files);
    const result = await composeKoaRouterEntrypoints(repo.root, repo.files, graph, []);
    assert.deepEqual(result.entrypoints, []);
  } finally {
    await repo.cleanup();
  }
});

test("Koa composition validates output bounds", async () => {
  const source = [
    'import Router from "@koa/router";',
    "const router = new Router();",
    "function status(ctx) { return true; }",
    'router.get("/status", status);',
  ].join("\n");
  const repo = await makeRepository({ "routes.ts": source });
  try {
    const graph = await buildCallGraph(repo.root, repo.files);
    await assert.rejects(
      composeKoaRouterEntrypoints(repo.root, repo.files, graph, [], { maxRoutes: 0 }),
      /maxRoutes must be an integer between 1 and 10000/,
    );
  } finally {
    await repo.cleanup();
  }
});
