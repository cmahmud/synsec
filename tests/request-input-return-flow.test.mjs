import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { findingRequestInputReturnFlowEvidence } from "@synsec/repository/request-input-return-flow";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function makeRepository(filesByPath) {
  const root = await mkdtemp(join(tmpdir(), "synsec-request-return-flow-"));
  const files = [];
  for (const [path, content] of Object.entries(filesByPath)) {
    const absolute = join(root, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, content, "utf8");
    files.push({ path, size: Buffer.byteLength(content) });
  }
  return { root, files, cleanup: () => rm(root, { recursive: true, force: true }) };
}

async function analyze(repo, options = {}) {
  const index = await buildRepositoryIndex(repo.root, repo.files);
  const moduleGraph = buildModuleGraph(index, repo.files);
  return buildRepositoryRouteFlowAnalysis(repo.root, repo.files, index, moduleGraph, options);
}

test("return flow links an exact helper request return through one immutable caller binding to a sink", async () => {
  const repo = await makeRepository({
    "server.ts": [
      "function readName(req) {",
      "  return req.body.name;",
      "}",
      "function persistName(name) {",
      "  db.query(name);",
      "}",
      "function createUser(req) {",
      "  const name = readName(req);",
      "  persistName(name);",
      "}",
      'router.post("/users", createUser);',
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    assert.equal(analysis.requestInputReturnFlows.length, 1);
    const context = analysis.requestInputReturnFlows[0];
    assert.equal(context?.interpretation, "structural-request-source-return-binding-call-sink-evidence-only");
    assert.deepEqual(context?.sourceKinds, ["body"]);
    assert.deepEqual(context?.sinkKinds, ["database"]);
    assert.equal(context?.evidence[0]?.source.functionName, "readName");
    assert.equal(context?.evidence[0]?.bridge.callerFunctionName, "createUser");
    assert.equal(context?.evidence[0]?.bridge.helperCallLine, 8);
    assert.equal(context?.evidence[0]?.bridge.forwardingCallLine, 9);
    assert.equal(context?.evidence[0]?.sink.functionName, "persistName");
    assert.equal(context?.evidence[0]?.callDistance, 1);
    assert.equal(context?.evidence[0]?.callScope, "same-file");

    const finding = findingRequestInputReturnFlowEvidence(analysis.requestInputReturnFlows, "server.ts", 5);
    assert.deepEqual(finding.map(({ sourceKind, sourceFunction, sinkKind, sinkFunction, interpretation }) => ({
      sourceKind, sourceFunction, sinkKind, sinkFunction, interpretation,
    })), [{
      sourceKind: "body",
      sourceFunction: "readName",
      sinkKind: "database",
      sinkFunction: "persistName",
      interpretation: "structural-request-source-return-binding-call-sink-evidence-only",
    }]);
  } finally {
    await repo.cleanup();
  }
});

test("return flow crosses one explicit repository-local named import without treating the import as runtime proof", async () => {
  const repo = await makeRepository({
    "server.ts": [
      'import { readName } from "./input.js";',
      'import { persistName } from "./store.js";',
      "function createUser(req) {",
      "  const name = readName(req);",
      "  persistName(name);",
      "}",
      'router.post("/users", createUser);',
    ].join("\n"),
    "input.ts": [
      "export function readName(req) {",
      "  return req.body.name;",
      "}",
    ].join("\n"),
    "store.ts": [
      "export function persistName(name) {",
      "  db.query(name);",
      "}",
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    assert.equal(analysis.requestInputReturnFlows.length, 1);
    assert.equal(analysis.requestInputReturnFlows[0]?.evidence[0]?.callScope, "same-file-and-explicit-imports");
    assert.equal(analysis.requestInputReturnFlows[0]?.evidence[0]?.source.functionName, "readName");
    assert.equal(analysis.requestInputReturnFlows[0]?.evidence[0]?.sink.functionName, "persistName");
  } finally {
    await repo.cleanup();
  }
});

test("return flow fails closed when the helper transforms the request value", async () => {
  const repo = await makeRepository({
    "server.ts": [
      "function readName(req) {",
      "  return req.body.name.trim();",
      "}",
      "function persistName(name) { db.query(name); }",
      "function createUser(req) {",
      "  const name = readName(req);",
      "  persistName(name);",
      "}",
      'router.post("/users", createUser);',
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    assert.deepEqual(analysis.requestInputReturnFlows, []);
  } finally {
    await repo.cleanup();
  }
});

test("return flow fails closed for multiple returns, aliasing, mutation, or multiple uses", async () => {
  const cases = [
    [
      "function readName(req) {",
      "  if (req.query.raw) return req.body.name;",
      "  return req.body.name;",
      "}",
      "function persistName(name) { db.query(name); }",
      "function createUser(req) { const name = readName(req); persistName(name); }",
      'router.post("/users", createUser);',
    ],
    [
      "function readName(req) { return req.body.name; }",
      "function persistName(name) { db.query(name); }",
      "function createUser(req) {",
      "  const name = readName(req);",
      "  const alias = name;",
      "  persistName(alias);",
      "}",
      'router.post("/users", createUser);',
    ],
    [
      "function readName(req) { return req.body.name; }",
      "function persistName(name) { db.query(name); }",
      "function createUser(req) {",
      "  const name = readName(req);",
      "  console.log(name);",
      "  persistName(name);",
      "}",
      'router.post("/users", createUser);',
    ],
  ];
  for (const lines of cases) {
    const repo = await makeRepository({ "server.ts": lines.join("\n") });
    try {
      const analysis = await analyze(repo);
      assert.deepEqual(analysis.requestInputReturnFlows, []);
    } finally {
      await repo.cleanup();
    }
  }
});

test("return flow enforces a bounded forwarding window", async () => {
  const repo = await makeRepository({
    "server.ts": [
      "function readName(req) {",
      "  return req.body.name;",
      "}",
      "function persistName(name) {",
      "  db.query(name);",
      "}",
      "function createUser(req) {",
      "  const name = readName(req);",
      "  noop();",
      "  noop();",
      "  persistName(name);",
      "}",
      'router.post("/users", createUser);',
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo, { maxRequestInputReturnForwardLines: 2 });
    assert.deepEqual(analysis.requestInputReturnFlows, []);
    await assert.rejects(
      analyze(repo, { maxRequestInputReturnForwardLines: 41 }),
      /maxForwardLines must be an integer between 1 and 40/,
    );
  } finally {
    await repo.cleanup();
  }
});
