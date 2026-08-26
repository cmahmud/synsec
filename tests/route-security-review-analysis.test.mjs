import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function fixture(source) {
  const root = await mkdtemp(join(tmpdir(), "synsec-route-security-review-"));
  await writeFile(join(root, "server.ts"), source, "utf8");
  return {
    root,
    inventory: [{ path: "server.ts", size: Buffer.byteLength(source) }],
  };
}

test("composed route-flow analysis includes minimized route security reviews", async (t) => {
  const source = [
    "const router = { post() {} };",
    "const requireAuth = () => true;",
    "router.post('/jobs', requireAuth, runJob);",
    "",
    "function runJob() {",
    "  return executeJob();",
    "}",
    "",
    "function executeJob() {",
    "  return db.query('select secret from jobs');",
    "}",
  ].join("\n");
  const { root, inventory } = await fixture(source);
  t.after(() => rm(root, { recursive: true, force: true }));

  const index = await buildRepositoryIndex(root, inventory);
  const moduleGraph = buildModuleGraph(index, inventory);
  const analysis = await buildRepositoryRouteFlowAnalysis(root, inventory, index, moduleGraph);

  assert.equal(analysis.routeSecurityReviews.length, 1);
  assert.deepEqual(analysis.routeSecurityReviews[0], {
    method: "POST",
    route: "/jobs",
    frameworkHint: "Node HTTP router",
    handler: "runJob",
    sinkKinds: ["database"],
    protectionStatus: "authentication-signal-observed",
    signal: "sensitive-sink-with-authentication-signal",
    callScope: "same-file",
    interpretation: "structural-route-security-review-context-only",
  });
  assert.equal(JSON.stringify(analysis.routeSecurityReviews).includes("select secret"), false);
  assert.equal(JSON.stringify(analysis.routeSecurityReviews).includes("server.ts"), false);
});
