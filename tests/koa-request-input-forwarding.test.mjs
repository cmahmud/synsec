import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildCallGraph } from "@synsec/repository/call-graph";
import {
  buildKoaRouteRequestInputForwardingContexts,
  findingKoaRequestInputForwardingEvidence,
} from "@synsec/repository/koa-request-input-forwarding";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function makeRepository(files) {
  const root = await mkdtemp(join(tmpdir(), "synsec-koa-request-forwarding-"));
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

test("Koa single-use local request input forwards into one exact helper sink", async () => {
  const source = [
    'import Router from "@koa/router";',
    "const router = new Router();",
    "function runJob(ctx) {",
    "  const command = ctx.request.body.command;",
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
    const flow = analysis.koaRequestInputForwardingFlows.find((item) => item.route.route === "/run");
    assert.equal(flow?.interpretation, "structural-koa-context-source-single-use-local-call-sink-evidence-only");
    assert.deepEqual(flow?.evidence.map((item) => ({
      sourceKind: item.source.kind,
      sourceLine: item.source.line,
      useLine: item.binding.useLine,
      sinkKind: item.sink.kind,
      sinkLine: item.sink.line,
      callDistance: item.callDistance,
    })), [{
      sourceKind: "body",
      sourceLine: 4,
      useLine: 5,
      sinkKind: "process",
      sinkLine: 8,
      callDistance: 1,
    }]);
    assert.deepEqual(findingKoaRequestInputForwardingEvidence(analysis.koaRequestInputForwardingFlows, "routes.ts", 8), [{
      method: "POST",
      route: "/run",
      frameworkHint: "Koa router",
      handler: "runJob",
      sourceKind: "body",
      sourceFunction: "runJob",
      sinkKind: "process",
      sinkFunction: "execute",
      callDistance: 1,
      bindingHops: 1,
      interpretation: "structural-koa-context-source-single-use-local-call-sink-evidence-only",
    }]);
  } finally {
    await repo.cleanup();
  }
});

test("Koa single-use local supports direct member-qualified database sink", async () => {
  const source = [
    'import Router from "@koa/router";',
    "const router = new Router();",
    "async function search(ctx) {",
    "  const term = ctx.query.term;",
    "  await db.query(term);",
    "}",
    'router.get("/search", search);',
  ].join("\n");
  const repo = await makeRepository({ "routes.ts": source });
  try {
    const analysis = await analyze(repo);
    const flow = analysis.koaRequestInputForwardingFlows.find((item) => item.route.route === "/search");
    assert.deepEqual(flow?.evidence.map((item) => [item.source.kind, item.sink.kind, item.callDistance]), [
      ["query", "database", 0],
    ]);
  } finally {
    await repo.cleanup();
  }
});

test("Koa forwarding fails closed on multiple use, transformation and mutable bindings", async () => {
  const variants = [
    ["multiple", [
      "function run(ctx) {",
      "  const command = ctx.query.command;",
      "  audit(command);",
      "  execute(command);",
      "}",
    ]],
    ["transform", [
      "function run(ctx) {",
      "  const command = ctx.query.command;",
      "  execute(command.trim());",
      "}",
    ]],
    ["mutable", [
      "function run(ctx) {",
      "  let command = ctx.query.command;",
      "  execute(command);",
      "}",
    ]],
  ];
  for (const [name, handler] of variants) {
    const source = [
      'import Router from "@koa/router";',
      "const router = new Router();",
      ...handler,
      "function execute(command) { child_process.exec(command); }",
      'router.post("/run", run);',
    ].join("\n");
    const repo = await makeRepository({ [`${name}.ts`]: source });
    try {
      const analysis = await analyze(repo);
      assert.deepEqual(analysis.koaRequestInputForwardingFlows, [], name);
    } finally {
      await repo.cleanup();
    }
  }
});

test("Koa forwarding rejects response body and generic Node routes", async () => {
  const koa = [
    'import Router from "@koa/router";',
    "const router = new Router();",
    "function run(ctx) {",
    "  const command = ctx.body.command;",
    "  execute(command);",
    "}",
    "function execute(command) { child_process.exec(command); }",
    'router.post("/run", run);',
  ].join("\n");
  const generic = [
    "function run(ctx) {",
    "  const command = ctx.query.command;",
    "  execute(command);",
    "}",
    "function execute(command) { child_process.exec(command); }",
    'router.post("/generic", run);',
  ].join("\n");
  const repo = await makeRepository({ "koa.ts": koa, "generic.ts": generic });
  try {
    const analysis = await analyze(repo);
    assert.deepEqual(analysis.koaRequestInputForwardingFlows, []);
  } finally {
    await repo.cleanup();
  }
});

test("Koa forwarding honors forward-line and evidence bounds", async () => {
  const source = [
    'import Router from "@koa/router";',
    "const router = new Router();",
    "function run(ctx) {",
    "  const command = ctx.get(\"x-command\");",
    "",
    "",
    "  execute(command);",
    "}",
    "function execute(command) { child_process.exec(command); }",
    'router.post("/run", run);',
  ].join("\n");
  const repo = await makeRepository({ "routes.ts": source });
  try {
    const bounded = await analyze(repo, { maxKoaRequestInputForwardLines: 2 });
    assert.deepEqual(bounded.koaRequestInputForwardingFlows, []);
    const graph = await buildCallGraph(repo.root, repo.files);
    await assert.rejects(
      buildKoaRouteRequestInputForwardingContexts(repo.root, [], graph, { maxEvidence: 0 }),
      /Koa request-forwarding maxEvidence must be an integer between 1 and 50/,
    );
  } finally {
    await repo.cleanup();
  }
});
