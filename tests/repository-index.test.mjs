import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildRepositoryIndex,
  readRepositoryIndex,
  writeRepositoryIndex,
} from "../packages/repository/dist/analysis.js";

test("repository index extracts imports, routes, auth context, and sensitive sinks without executing code", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-index-test-"));
  try {
    await mkdir(join(root, "src"));
    const source = `import express from "express";
import { execFile } from "node:child_process";
const app = express();
function requireAuth(req, res, next) { return next(); }
app.get("/users/:id", requireAuth, async (req, res) => {
  const rows = await db.query("select * from users where id = $1", [req.params.id]);
  res.json(rows);
});
execFile("echo", ["fixture"]);
`;
    await writeFile(join(root, "src", "app.ts"), source);

    const index = await buildRepositoryIndex(root, [{ path: "src/app.ts", size: Buffer.byteLength(source) }]);
    assert.equal(index.schemaVersion, 1);
    assert.equal(index.indexedFileCount, 1);
    assert.ok(index.moduleEdges.some((edge) => edge.specifier === "express"));
    assert.ok(index.routes.some((route) => route.route === "/users/:id" && route.method === "GET"));
    assert.ok(index.authSignals.some((signal) => signal.kind === "authentication"));
    assert.ok(index.sinks.some((sink) => sink.kind === "database"));
    assert.ok(index.sinks.some((sink) => sink.kind === "process"));

    const output = join(root, ".synsec", "repository-index.json");
    await writeRepositoryIndex(output, index);
    const reloaded = await readRepositoryIndex(output);
    assert.equal(reloaded.routes[0].route, "/users/:id");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
