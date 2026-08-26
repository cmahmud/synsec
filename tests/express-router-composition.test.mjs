import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildCallGraph } from "@synsec/repository/call-graph";
import { composeExpressRouterEntrypoints } from "@synsec/repository/express-router-composition";
import { resolveImportedNodeRouteEntrypoints } from "@synsec/repository/import-route-handlers";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { resolveRouteEntrypoints } from "@synsec/repository/route-entrypoints";

async function makeRepository(filesByPath) {
  const root = await mkdtemp(join(tmpdir(), "synsec-express-router-composition-"));
  const files = [];
  for (const [path, content] of Object.entries(filesByPath)) {
    const absolute = join(root, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, content, "utf8");
    files.push({ path, size: Buffer.byteLength(content) });
  }
  return { root, files, cleanup: () => rm(root, { recursive: true, force: true }) };
}

async function compose(repo, options) {
  const index = await buildRepositoryIndex(repo.root, repo.files);
  const moduleGraph = buildModuleGraph(index, repo.files);
  const callGraph = await buildCallGraph(repo.root, repo.files);
  let entrypoints = resolveRouteEntrypoints(index, callGraph);
  entrypoints = await resolveImportedNodeRouteEntrypoints(repo.root, repo.files, moduleGraph, callGraph, entrypoints);
  return composeExpressRouterEntrypoints(repo.root, repo.files, moduleGraph, entrypoints, options);
}

function composed(entrypoints) {
  return entrypoints.filter((entrypoint) => entrypoint.route.frameworkHint === "Express composed router");
}

test("Express default-imported routers compose literal app mount prefixes", async () => {
  const repo = await makeRepository({
    "app.js": [
      'import express from "express";',
      'import usersRouter from "./users.js";',
      "const app = express();",
      'app.use("/api", usersRouter);',
    ].join("\n"),
    "users.js": [
      'import express from "express";',
      "const router = express.Router();",
      'router.get("/users/:id", getUser);',
      "function getUser(req, res) {",
      "  database.query(sql);",
      "}",
      "export default router;",
    ].join("\n"),
  });
  try {
    const routes = composed(await compose(repo));
    assert.equal(routes.length, 1);
    assert.equal(routes[0]?.route.route, "/api/users/:id");
    assert.equal(routes[0]?.handler?.name, "getUser");
    assert.equal(routes[0]?.handler?.path, "users.js");
    assert.equal(routes[0]?.calls?.root, routes[0]?.handler?.id);
    assert.equal(routes[0]?.compositionInterpretation, "structural-express-router-composition-not-runtime-reachability");
  } finally { await repo.cleanup(); }
});

test("Express nested router mounts compose only within the configured bound", async () => {
  const repo = await makeRepository({
    "app.js": ['import express from "express";', 'import apiRouter from "./api.js";', "const app = express();", 'app.use("/api", apiRouter);'].join("\n"),
    "api.js": ['import express from "express";', 'import usersRouter from "./users.js";', "const router = express.Router();", 'router.use("/v1", usersRouter);', "export default router;"].join("\n"),
    "users.js": ['import express from "express";', "const router = express.Router();", 'router.post("/users", createUser);', "function createUser() { return true; }", "export default router;"].join("\n"),
  });
  try {
    const all = composed(await compose(repo));
    assert.equal(all.length, 1);
    assert.equal(all[0]?.route.route, "/api/v1/users");
    assert.equal(all[0]?.composition?.mountDepth, 2);
    assert.deepEqual(composed(await compose(repo, { maxMountDepth: 1 })), []);
  } finally { await repo.cleanup(); }
});

test("Express dynamic prefixes and router factories fail closed", async () => {
  const repo = await makeRepository({
    "app.js": ['import express from "express";', 'import usersRouter from "./users.js";', "const app = express();", 'const prefix = "/api";', "app.use(prefix, usersRouter);"].join("\n"),
    "users.js": ['import express from "express";', "const router = makeRouter();", 'router.get("/users", listUsers);', "function listUsers() { return true; }", "export default router;"].join("\n"),
  });
  try { assert.deepEqual(composed(await compose(repo)), []); }
  finally { await repo.cleanup(); }
});

test("Express shadowed imported router bindings fail closed", async () => {
  const repo = await makeRepository({
    "app.js": ['import express from "express";', 'import usersRouter from "./users.js";', "const app = express();", "usersRouter = makeRouter();", 'app.use("/api", usersRouter);'].join("\n"),
    "users.js": ['import express from "express";', "const router = express.Router();", 'router.get("/users", listUsers);', "function listUsers() { return true; }", "export default router;"].join("\n"),
  });
  try { assert.deepEqual(composed(await compose(repo)), []); }
  finally { await repo.cleanup(); }
});

test("Express use-before-declaration does not create composition evidence", async () => {
  const repo = await makeRepository({
    "app.js": ['import express from "express";', "const app = express();", 'app.use("/api", router);', "const router = express.Router();", 'router.get("/late", late);', "function late() { return true; }"].join("\n"),
  });
  try { assert.deepEqual(composed(await compose(repo)), []); }
  finally { await repo.cleanup(); }
});
