import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";
import { findingRequestInputFlowEvidence } from "@synsec/repository/request-input-flow";
import { findingRequestInputForwardingEvidence } from "@synsec/repository/request-input-forwarding";

async function makeRepository(filesByPath) {
  const root = await mkdtemp(join(tmpdir(), "synsec-request-input-flow-"));
  const files = [];
  for (const [path, content] of Object.entries(filesByPath)) {
    const absolute = join(root, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, content, "utf8");
    files.push({ path, size: Buffer.byteLength(content) });
  }
  return { root, files, cleanup: () => rm(root, { recursive: true, force: true }) };
}

test("request input flow crosses an explicit import only from a source-bearing outbound call", async () => {
  const repo = await makeRepository({
    "server.ts": [
      'import { saveUser } from "./service.js";',
      "export function createUser(req) {",
      "  saveUser(req.body.name);",
      "}",
      'router.post("/users", createUser);',
    ].join("\n"),
    "service.ts": [
      "export function saveUser(name) {",
      "  db.query(sql, [name]);",
      "}",
    ].join("\n"),
  });

  try {
    const index = await buildRepositoryIndex(repo.root, repo.files);
    const moduleGraph = buildModuleGraph(index, repo.files);
    const analysis = await buildRepositoryRouteFlowAnalysis(repo.root, repo.files, index, moduleGraph);

    assert.deepEqual(analysis.requestInputs, [{
      path: "server.ts",
      line: 3,
      kind: "body",
      frameworkFamily: "node-request",
      access: "request.body",
    }]);
    assert.equal(analysis.requestInputFlows.length, 1);
    const flow = analysis.requestInputFlows[0];
    assert.equal(flow?.callScope, "same-file-and-explicit-imports");
    assert.equal(flow?.interpretation, "structural-request-source-call-sink-evidence-only");
    assert.deepEqual(flow?.evidence.map((item) => ({
      sourcePath: item.source.path,
      sourceLine: item.source.line,
      sourceKind: item.source.kind,
      sourceFunction: item.source.functionName,
      sinkPath: item.sink.path,
      sinkLine: item.sink.line,
      sinkKind: item.sink.kind,
      sinkFunction: item.sink.functionName,
      callDistance: item.callDistance,
    })), [{
      sourcePath: "server.ts",
      sourceLine: 3,
      sourceKind: "body",
      sourceFunction: "createUser",
      sinkPath: "service.ts",
      sinkLine: 2,
      sinkKind: "database",
      sinkFunction: "saveUser",
      callDistance: 1,
    }]);

    const finding = findingRequestInputFlowEvidence(analysis.requestInputFlows, "service.ts", 2);
    assert.deepEqual(finding, [{
      method: "POST",
      route: "/users",
      frameworkHint: "Node HTTP router",
      resolution: "named-function",
      handler: "createUser",
      sourceKind: "body",
      sourceFunction: "createUser",
      sinkKind: "database",
      sinkFunction: "saveUser",
      callDistance: 1,
      callScope: "same-file-and-explicit-imports",
      interpretation: "structural-request-source-call-sink-evidence-only",
    }]);
    assert.equal(JSON.stringify(flow).includes("req.body.name"), false);
    assert.equal(JSON.stringify(flow).includes("sql"), false);
  } finally {
    await repo.cleanup();
  }
});

test("request source evidence does not jump to a sibling sink without a source-bearing call", async () => {
  const repo = await makeRepository({
    "server.ts": [
      "export function handler(req) {",
      "  consume(req.query.q);",
      "  unrelated();",
      "}",
      "function consume(value) {",
      "  return value;",
      "}",
      "function unrelated() {",
      "  db.query(secretSql);",
      "}",
      'router.get("/search", handler);',
    ].join("\n"),
  });
  try {
    const index = await buildRepositoryIndex(repo.root, repo.files);
    const moduleGraph = buildModuleGraph(index, repo.files);
    const analysis = await buildRepositoryRouteFlowAnalysis(repo.root, repo.files, index, moduleGraph);
    assert.equal(analysis.requestInputs.length, 1);
    assert.deepEqual(analysis.requestInputFlows, []);
    assert.deepEqual(analysis.requestInputForwardingFlows, []);
  } finally {
    await repo.cleanup();
  }
});

test("request input identification omits request-looking parameter names without explicit access", async () => {
  const repo = await makeRepository({
    "server.py": [
      "def handler(request):",
      "    save_user(request_id)",
      "",
      "def save_user(value):",
      "    db.execute(sql)",
      "",
      "@app.get('/users')",
      "def route_handler():",
      "    return handler(fake_request)",
    ].join("\n"),
  });
  try {
    const index = await buildRepositoryIndex(repo.root, repo.files);
    const moduleGraph = buildModuleGraph(index, repo.files);
    const analysis = await buildRepositoryRouteFlowAnalysis(repo.root, repo.files, index, moduleGraph);
    assert.deepEqual(analysis.requestInputs, []);
    assert.deepEqual(analysis.requestInputFlows, []);
    assert.deepEqual(analysis.requestInputForwardingFlows, []);
  } finally {
    await repo.cleanup();
  }
});

test("python request access categories are explicit and sanitized", async () => {
  const repo = await makeRepository({
    "app.py": [
      "def handler():",
      "    term = request.args.get('q')",
      "    run_query(term)",
      "",
      "def run_query(term):",
      "    db.execute(sql)",
      "",
      "@app.get('/search')",
      "def route_handler():",
      "    return handler()",
    ].join("\n"),
  });
  try {
    const index = await buildRepositoryIndex(repo.root, repo.files);
    const moduleGraph = buildModuleGraph(index, repo.files);
    const analysis = await buildRepositoryRouteFlowAnalysis(repo.root, repo.files, index, moduleGraph);
    assert.deepEqual(analysis.requestInputs, [{
      path: "app.py",
      line: 2,
      kind: "query",
      frameworkFamily: "python-request",
      access: "request.args",
    }]);
    assert.deepEqual(analysis.requestInputFlows, []);
    assert.deepEqual(analysis.requestInputForwardingFlows, []);
    assert.equal(JSON.stringify(analysis.requestInputs).includes("'q'"), false);
  } finally {
    await repo.cleanup();
  }
});

test("immutable single-use request binding forwards structurally through an explicit imported call", async () => {
  const repo = await makeRepository({
    "server.ts": [
      'import { saveUser } from "./service.js";',
      "export function createUser(req) {",
      "  const name = req.body.name;",
      "  saveUser(name);",
      "}",
      'router.post("/users", createUser);',
    ].join("\n"),
    "service.ts": [
      "export function saveUser(name) {",
      "  db.query(sql, [name]);",
      "}",
    ].join("\n"),
  });
  try {
    const index = await buildRepositoryIndex(repo.root, repo.files);
    const moduleGraph = buildModuleGraph(index, repo.files);
    const analysis = await buildRepositoryRouteFlowAnalysis(repo.root, repo.files, index, moduleGraph);

    assert.deepEqual(analysis.requestInputFlows, []);
    assert.equal(analysis.requestInputForwardingFlows.length, 1);
    const flow = analysis.requestInputForwardingFlows[0];
    assert.equal(flow?.interpretation, "structural-request-source-immutable-binding-call-sink-evidence-only");
    assert.equal(flow?.callScope, "same-file-and-explicit-imports");
    assert.deepEqual(flow?.evidence.map((item) => ({
      sourceLine: item.source.line,
      declarationLine: item.forwarding.declarationLine,
      callLine: item.forwarding.callLine,
      forwardingKind: item.forwarding.kind,
      sinkPath: item.sink.path,
      sinkLine: item.sink.line,
      callDistance: item.callDistance,
    })), [{
      sourceLine: 3,
      declarationLine: 3,
      callLine: 4,
      forwardingKind: "immutable-local-binding-direct-call-argument",
      sinkPath: "service.ts",
      sinkLine: 2,
      callDistance: 1,
    }]);

    assert.deepEqual(findingRequestInputForwardingEvidence(
      analysis.requestInputForwardingFlows,
      "service.ts",
      2,
    ), [{
      method: "POST",
      route: "/users",
      frameworkHint: "Node HTTP router",
      resolution: "named-function",
      handler: "createUser",
      sourceKind: "body",
      sourceFunction: "createUser",
      sinkKind: "database",
      sinkFunction: "saveUser",
      callDistance: 1,
      callScope: "same-file-and-explicit-imports",
      interpretation: "structural-request-source-immutable-binding-call-sink-evidence-only",
    }]);
    assert.equal(JSON.stringify(flow).includes("name ="), false);
    assert.equal(JSON.stringify(flow).includes("req.body.name"), false);
  } finally {
    await repo.cleanup();
  }
});

test("request forwarding fails closed on mutation, transformation, multiple use, and unresolved calls", async () => {
  const cases = [
    ["mutation", [
      "export function handler(req) {",
      "  const term = req.query.term;",
      "  term = normalize(term);",
      "  runQuery(term);",
      "}",
      "function runQuery(term) { db.query(sql); }",
      'router.get("/search", handler);',
    ]],
    ["transformation", [
      "export function handler(req) {",
      "  const term = req.query.term;",
      "  runQuery(normalize(term));",
      "}",
      "function runQuery(term) { db.query(sql); }",
      'router.get("/search", handler);',
    ]],
    ["multiple-use", [
      "export function handler(req) {",
      "  const term = req.query.term;",
      "  audit(term);",
      "  runQuery(term);",
      "}",
      "function audit(term) { return term; }",
      "function runQuery(term) { db.query(sql); }",
      'router.get("/search", handler);',
    ]],
    ["unresolved", [
      "export function handler(req) {",
      "  const term = req.query.term;",
      "  externalClient.send(term);",
      "}",
      'router.get("/search", handler);',
      "function localSink() { db.query(sql); }",
    ]],
  ];

  for (const [name, lines] of cases) {
    const repo = await makeRepository({ [`${name}.ts`]: lines.join("\n") });
    try {
      const index = await buildRepositoryIndex(repo.root, repo.files);
      const moduleGraph = buildModuleGraph(index, repo.files);
      const analysis = await buildRepositoryRouteFlowAnalysis(repo.root, repo.files, index, moduleGraph);
      assert.deepEqual(analysis.requestInputForwardingFlows, [], name);
    } finally {
      await repo.cleanup();
    }
  }
});
