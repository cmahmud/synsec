import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { composeNestJsControllerEntrypoints } from "@synsec/repository/nestjs-controller-composition";
import { buildCallGraph } from "@synsec/repository/call-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function makeRepository(content) {
  const root = await mkdtemp(join(tmpdir(), "synsec-nestjs-controller-"));
  const path = "admin.controller.ts";
  await writeFile(join(root, path), content, "utf8");
  return {
    root,
    files: [{ path, size: Buffer.byteLength(content) }],
    cleanup: () => rm(root, { recursive: true, force: true }),
  };
}

test("NestJS controller routes compose literal prefixes and preserve exact sink evidence", async () => {
  const source = [
    'import { Controller, Post, UseGuards } from "@nestjs/common";',
    "@Controller(\"admin\")",
    "@UseGuards(SessionGuard)",
    "export class AdminController {",
    "  @Post(\"run\")",
    "  @UseGuards(AdminGuard)",
    "  run() {",
    "    child_process.exec(command);",
    "  }",
    "}",
  ].join("\n");
  const repo = await makeRepository(source);
  try {
    const index = await buildRepositoryIndex(repo.root, repo.files);
    const analysis = await buildRepositoryRouteFlowAnalysis(repo.root, repo.files, index, buildModuleGraph(index, repo.files));
    const entrypoint = analysis.entrypoints.find((item) => item.route.frameworkHint === "NestJS controller");
    assert.equal(entrypoint?.route.method, "POST");
    assert.equal(entrypoint?.route.route, "/admin/run");
    assert.equal(entrypoint?.handler?.name, "run");
    assert.equal(entrypoint?.resolution, "decorated-function");

    const flow = analysis.routeFlows.find((item) => item.route.frameworkHint === "NestJS controller");
    assert.deepEqual(flow?.evidence.map((item) => ({ path: item.path, line: item.line, kind: item.kind, depth: item.depth })), [
      { path: "admin.controller.ts", line: 8, kind: "process", depth: 0 },
    ]);
    assert.equal(flow?.interpretation, "structural-route-call-sink-evidence-only");

    const guards = analysis.nestJsGuardContexts.find((item) => item.route.route === "/admin/run");
    assert.deepEqual(guards?.guards, [
      { name: "SessionGuard", line: 3, scope: "controller" },
      { name: "AdminGuard", line: 6, scope: "method" },
    ]);
    assert.equal(guards?.interpretation, "structural-nestjs-guard-attachment-not-runtime-protection");
  } finally {
    await repo.cleanup();
  }
});

test("NestJS composition accepts empty literal route decorators", async () => {
  const source = [
    'import { Controller, Get } from "@nestjs/common";',
    "@Controller(\"health\")",
    "export class HealthController {",
    "  @Get()",
    "  status() {",
    "    return true;",
    "  }",
    "}",
  ].join("\n");
  const repo = await makeRepository(source);
  try {
    const graph = await buildCallGraph(repo.root, repo.files);
    const result = await composeNestJsControllerEntrypoints(repo.root, repo.files, graph, []);
    assert.equal(result.entrypoints.length, 1);
    assert.equal(result.entrypoints[0]?.route.route, "/health");
    assert.equal(result.entrypoints[0]?.route.method, "GET");
  } finally {
    await repo.cleanup();
  }
});

test("NestJS composition fails closed on dynamic controller prefixes", async () => {
  const source = [
    'import { Controller, Get } from "@nestjs/common";',
    "@Controller(API_PREFIX)",
    "export class DynamicController {",
    "  @Get(\"status\")",
    "  status() { return true; }",
    "}",
  ].join("\n");
  const repo = await makeRepository(source);
  try {
    const graph = await buildCallGraph(repo.root, repo.files);
    const result = await composeNestJsControllerEntrypoints(repo.root, repo.files, graph, []);
    assert.deepEqual(result.entrypoints, []);
    assert.deepEqual(result.guardContexts, []);
  } finally {
    await repo.cleanup();
  }
});

test("NestJS composition fails closed on aliased framework decorators", async () => {
  const source = [
    'import { Controller as NestController, Get } from "@nestjs/common";',
    "@NestController(\"api\")",
    "export class AliasController {",
    "  @Get(\"status\")",
    "  status() { return true; }",
    "}",
  ].join("\n");
  const repo = await makeRepository(source);
  try {
    const graph = await buildCallGraph(repo.root, repo.files);
    const result = await composeNestJsControllerEntrypoints(repo.root, repo.files, graph, []);
    assert.deepEqual(result.entrypoints, []);
  } finally {
    await repo.cleanup();
  }
});

test("NestJS composition does not treat guard factories as structural guard evidence", async () => {
  const source = [
    'import { Controller, Get, UseGuards } from "@nestjs/common";',
    "@Controller(\"api\")",
    "export class GuardedController {",
    "  @Get(\"status\")",
    "  @UseGuards(AuthGuard(\"jwt\"))",
    "  status() {",
    "    return true;",
    "  }",
    "}",
  ].join("\n");
  const repo = await makeRepository(source);
  try {
    const graph = await buildCallGraph(repo.root, repo.files);
    const result = await composeNestJsControllerEntrypoints(repo.root, repo.files, graph, []);
    assert.deepEqual(result.guardContexts, []);
    assert.deepEqual(result.entrypoints, []);
  } finally {
    await repo.cleanup();
  }
});

test("NestJS composition validates output bounds", async () => {
  const source = [
    'import { Controller, Get } from "@nestjs/common";',
    "@Controller(\"api\")",
    "export class ApiController {",
    "  @Get(\"status\")",
    "  status() { return true; }",
    "}",
  ].join("\n");
  const repo = await makeRepository(source);
  try {
    const graph = await buildCallGraph(repo.root, repo.files);
    await assert.rejects(
      composeNestJsControllerEntrypoints(repo.root, repo.files, graph, [], { maxRoutes: 0 }),
      /maxRoutes must be an integer between 1 and 10000/,
    );
  } finally {
    await repo.cleanup();
  }
});
