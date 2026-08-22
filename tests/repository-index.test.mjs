import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildRepositoryIndex,
  findDependencyUsage,
  findingRepositoryContext,
  packageNameFromPurl,
  readRepositoryIndex,
  routeSecurityContext,
  writeRepositoryIndex,
} from "../packages/repository/dist/analysis.js";

test("repository index extracts imports, routes, auth context, and sensitive sinks without executing code", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-index-test-"));
  try {
    await mkdir(join(root, "src"));
    const source = `import express from "express";
import { execFile } from "node:child_process";
import lodash from "lodash/fp";
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

    const lodashUsage = findDependencyUsage(index, "lodash");
    assert.equal(lodashUsage.status, "observed-import");
    assert.equal(lodashUsage.evidence[0].specifier, "lodash/fp");
    assert.equal(findDependencyUsage(index, "not-imported").status, "unknown");
    assert.equal(packageNameFromPurl("pkg:npm/%40scope/demo@1.2.3"), "@scope/demo");

    const route = index.routes.find((item) => item.route === "/users/:id");
    assert.ok(route);
    const context = routeSecurityContext(index, route);
    assert.ok(context.nearbyAuthSignals.some((signal) => signal.kind === "authentication"));
    assert.ok(context.nearbySinks.some((sink) => sink.kind === "database"));

    const findingContext = findingRepositoryContext(index, "./src/app.ts", 7, 5);
    assert.equal(findingContext.interpretation, "proximity-signals-only");
    assert.ok(findingContext.nearbyRoutes.some((signal) => signal.route === "/users/:id"));
    assert.ok(findingContext.nearbyAuthSignals.some((signal) => signal.kind === "authentication"));
    assert.ok(findingContext.nearbySinks.some((signal) => signal.kind === "database"));
    assert.equal("evidence" in findingContext.nearbyAuthSignals[0], false);
    assert.equal("evidence" in findingContext.nearbySinks[0], false);

    const output = join(root, ".synsec", "repository-index.json");
    await writeRepositoryIndex(output, index);
    const reloaded = await readRepositoryIndex(output);
    assert.equal(reloaded.routes[0].route, "/users/:id");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
