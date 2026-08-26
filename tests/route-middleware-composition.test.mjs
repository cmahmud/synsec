import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function makeRepository(filesByPath) {
  const root = await mkdtemp(join(tmpdir(), "synsec-route-middleware-"));
  const files = [];
  for (const [path, content] of Object.entries(filesByPath)) {
    const absolute = join(root, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, content, "utf8");
    files.push({ path, size: Buffer.byteLength(content) });
  }
  return { root, files, cleanup: () => rm(root, { recursive: true, force: true }) };
}

async function analyze(repo) {
  const index = await buildRepositoryIndex(repo.root, repo.files);
  return buildRepositoryRouteFlowAnalysis(repo.root, repo.files, index, buildModuleGraph(index, repo.files));
}

test("route middleware composition resolves same-file named middleware and bounds auth evidence", async () => {
  const repo = await makeRepository({
    "server.ts": [
      "function requireAdmin(req, res, next) {",
      "  authorize(req.user);",
      "  next();",
      "}",
      "function createUser(req, res) {",
      "  db.query(req.body.name);",
      "}",
      'router.post("/users", requireAdmin, createUser);',
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    assert.equal(analysis.routeMiddlewareContexts.length, 1);
    const context = analysis.routeMiddlewareContexts[0];
    assert.equal(context?.handler, "createUser");
    assert.equal(context?.middleware[0]?.name, "requireAdmin");
    assert.equal(context?.middleware[0]?.resolution, "same-file-function");
    assert.equal(context?.status, "authorization-signal-observed");
    assert.deepEqual(context?.authEvidence.map(({ path, line, kind, middleware, depth }) => ({
      path, line, kind, middleware, depth,
    })), [{
      path: "server.ts",
      line: 2,
      kind: "authorization",
      middleware: "requireAdmin",
      depth: 0,
    }]);
    assert.equal(context?.interpretation, "structural-route-middleware-evidence-not-runtime-protection");
  } finally {
    await repo.cleanup();
  }
});

test("route middleware composition resolves explicit named imports and bounded helper calls", async () => {
  const repo = await makeRepository({
    "server.ts": [
      'import { requireAuth } from "./auth.js";',
      "function handler(req, res) {",
      "  db.query(req.body.id);",
      "}",
      'router.get("/account", requireAuth, handler);',
    ].join("\n"),
    "auth.ts": [
      "export function requireAuth(req, res, next) {",
      "  verifySession(req);",
      "  next();",
      "}",
      "function verifySession(req) {",
      "  authentication(req.session);",
      "}",
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    const context = analysis.routeMiddlewareContexts[0];
    assert.equal(context?.middleware[0]?.resolution, "imported-named-function");
    assert.equal(context?.callScope, "middleware-and-bounded-callees");
    assert.equal(context?.status, "authentication-signal-observed");
    assert.equal(context?.authEvidence.some((item) => item.path === "auth.ts" && item.line === 6 && item.depth === 1), true);
  } finally {
    await repo.cleanup();
  }
});

test("route middleware composition fails closed for invoked or otherwise dynamic middleware expressions", async () => {
  const repo = await makeRepository({
    "server.ts": [
      "function requireAuth() { return (_req, _res, next) => next(); }",
      "function handler(req, res) { db.query(req.body.id); }",
      'router.get("/account", requireAuth(), handler);',
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    assert.deepEqual(analysis.routeMiddlewareContexts, []);
  } finally {
    await repo.cleanup();
  }
});

test("route middleware composition refuses a shadowed imported binding", async () => {
  const repo = await makeRepository({
    "server.ts": [
      'import { requireAuth } from "./auth.js";',
      "requireAuth = replacement;",
      "function handler(req, res) { db.query(req.body.id); }",
      'router.get("/account", requireAuth, handler);',
    ].join("\n"),
    "auth.ts": [
      "export function requireAuth(req, res, next) {",
      "  authentication(req.session);",
      "  next();",
      "}",
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    const context = analysis.routeMiddlewareContexts[0];
    assert.equal(context?.middleware[0]?.resolution, "unresolved");
    assert.deepEqual(context?.authEvidence, []);
    assert.equal(context?.status, "no-auth-signal-observed");
  } finally {
    await repo.cleanup();
  }
});
