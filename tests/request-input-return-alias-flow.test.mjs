import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import {
  findingRequestInputReturnAliasFlowEvidence,
  repositoryRouteRequestInputReturnAliasFlowContexts,
} from "@synsec/repository/request-input-return-alias-flow";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function makeRepository(filesByPath) {
  const root = await mkdtemp(join(tmpdir(), "synsec-request-return-alias-flow-"));
  const files = [];
  for (const [path, content] of Object.entries(filesByPath)) {
    const absolute = join(root, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, content, "utf8");
    files.push({ path, size: Buffer.byteLength(content) });
  }
  return { root, files, cleanup: () => rm(root, { recursive: true, force: true }) };
}

async function analyzeAlias(repo, options = {}) {
  const index = await buildRepositoryIndex(repo.root, repo.files);
  const moduleGraph = buildModuleGraph(index, repo.files);
  const analysis = await buildRepositoryRouteFlowAnalysis(repo.root, repo.files, index, moduleGraph);
  return repositoryRouteRequestInputReturnAliasFlowContexts(
    repo.root,
    repo.files,
    analysis.requestInputs,
    analysis.routeFlows,
    analysis.callGraph,
    analysis.importCallLinks,
    options,
  );
}

test("return alias flow links one exact immutable alias between helper return and sink", async () => {
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
      "  const persistedName = name;",
      "  persistName(persistedName);",
      "}",
      'router.post("/users", createUser);',
    ].join("\n"),
  });
  try {
    const contexts = await analyzeAlias(repo);
    assert.equal(contexts.length, 1);
    const context = contexts[0];
    assert.equal(context?.interpretation, "structural-request-source-return-two-immutable-bindings-call-sink-evidence-only");
    assert.deepEqual(context?.sourceKinds, ["body"]);
    assert.deepEqual(context?.sinkKinds, ["database"]);
    assert.equal(context?.evidence[0]?.source.functionName, "readName");
    assert.equal(context?.evidence[0]?.bridge.callerFunctionName, "createUser");
    assert.equal(context?.evidence[0]?.bridge.helperCallLine, 8);
    assert.equal(context?.evidence[0]?.bridge.aliasLine, 9);
    assert.equal(context?.evidence[0]?.bridge.forwardingCallLine, 10);
    assert.equal(context?.evidence[0]?.bridge.bindingHops, 2);
    assert.equal(context?.evidence[0]?.sink.functionName, "persistName");
    assert.equal(context?.evidence[0]?.callScope, "same-file");

    const finding = findingRequestInputReturnAliasFlowEvidence(contexts, "server.ts", 5);
    assert.deepEqual(finding.map(({ sourceKind, sinkKind, bindingHops, interpretation }) => ({
      sourceKind, sinkKind, bindingHops, interpretation,
    })), [{
      sourceKind: "body",
      sinkKind: "database",
      bindingHops: 2,
      interpretation: "structural-request-source-return-two-immutable-bindings-call-sink-evidence-only",
    }]);
    assert.deepEqual(findingRequestInputReturnAliasFlowEvidence(contexts, "server.ts", 6), []);
  } finally {
    await repo.cleanup();
  }
});

test("return alias flow crosses explicit repository-local imports without treating them as runtime proof", async () => {
  const repo = await makeRepository({
    "server.ts": [
      'import { readName } from "./input.js";',
      'import { persistName } from "./store.js";',
      "function createUser(req) {",
      "  const name = readName(req);",
      "  const persistedName = name;",
      "  persistName(persistedName);",
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
    const contexts = await analyzeAlias(repo);
    assert.equal(contexts.length, 1);
    assert.equal(contexts[0]?.evidence[0]?.callScope, "same-file-and-explicit-imports");
    assert.equal(contexts[0]?.evidence[0]?.source.functionName, "readName");
    assert.equal(contexts[0]?.evidence[0]?.sink.functionName, "persistName");
  } finally {
    await repo.cleanup();
  }
});

test("return alias flow fails closed for transformations, second aliases, and multiple uses", async () => {
  const cases = [
    [
      "function readName(req) { return req.body.name; }",
      "function persistName(name) { db.query(name); }",
      "function createUser(req) {",
      "  const name = readName(req);",
      "  const persistedName = name.trim();",
      "  persistName(persistedName);",
      "}",
      'router.post("/users", createUser);',
    ],
    [
      "function readName(req) { return req.body.name; }",
      "function persistName(name) { db.query(name); }",
      "function createUser(req) {",
      "  const name = readName(req);",
      "  const aliasOne = name;",
      "  const aliasTwo = aliasOne;",
      "  persistName(aliasTwo);",
      "}",
      'router.post("/users", createUser);',
    ],
    [
      "function readName(req) { return req.body.name; }",
      "function persistName(name) { db.query(name); }",
      "function createUser(req) {",
      "  const name = readName(req);",
      "  const persistedName = name;",
      "  console.log(persistedName);",
      "  persistName(persistedName);",
      "}",
      'router.post("/users", createUser);',
    ],
    [
      "function readName(req) { return req.body.name; }",
      "function persistName(name) { db.query(name); }",
      "function createUser(req) {",
      "  const name = readName(req);",
      "  console.log(name);",
      "  const persistedName = name;",
      "  persistName(persistedName);",
      "}",
      'router.post("/users", createUser);',
    ],
  ];
  for (const lines of cases) {
    const repo = await makeRepository({ "server.ts": lines.join("\n") });
    try {
      assert.deepEqual(await analyzeAlias(repo), []);
    } finally {
      await repo.cleanup();
    }
  }
});

test("return alias flow does not duplicate the existing direct-binding return shape", async () => {
  const repo = await makeRepository({
    "server.ts": [
      "function readName(req) { return req.body.name; }",
      "function persistName(name) { db.query(name); }",
      "function createUser(req) {",
      "  const name = readName(req);",
      "  persistName(name);",
      "}",
      'router.post("/users", createUser);',
    ].join("\n"),
  });
  try {
    assert.deepEqual(await analyzeAlias(repo), []);
  } finally {
    await repo.cleanup();
  }
});

test("return alias flow enforces one total bounded forwarding window", async () => {
  const repo = await makeRepository({
    "server.ts": [
      "function readName(req) {",
      "  return req.body.name;",
      "}",
      "function persistName(name) { db.query(name); }",
      "function createUser(req) {",
      "  const name = readName(req);",
      "  noop();",
      "  const persistedName = name;",
      "  noop();",
      "  persistName(persistedName);",
      "}",
      'router.post("/users", createUser);',
    ].join("\n"),
  });
  try {
    assert.deepEqual(await analyzeAlias(repo, { maxForwardLines: 3 }), []);
    const contexts = await analyzeAlias(repo, { maxForwardLines: 4 });
    assert.equal(contexts.length, 1);
    await assert.rejects(
      analyzeAlias(repo, { maxForwardLines: 1 }),
      /maxForwardLines must be an integer between 2 and 40/,
    );
    await assert.rejects(
      analyzeAlias(repo, { maxForwardLines: 41 }),
      /maxForwardLines must be an integer between 2 and 40/,
    );
  } finally {
    await repo.cleanup();
  }
});
