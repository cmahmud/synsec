import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";
import { findingRouteProtectionEvidence } from "@synsec/repository/route-protection-context";

async function fixture(files) {
  const root = await mkdtemp(join(tmpdir(), "synsec-route-protection-"));
  for (const [path, content] of Object.entries(files)) {
    await writeFile(join(root, path), content, "utf8");
  }
  const inventory = Object.entries(files).map(([path, content]) => ({ path, size: Buffer.byteLength(content) }));
  return { root, inventory };
}

test("composed repository route analysis carries minimized protection context alongside sink flow", async (t) => {
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
  const { root, inventory } = await fixture({ "server.ts": source });
  t.after(() => rm(root, { recursive: true, force: true }));

  const index = await buildRepositoryIndex(root, inventory);
  const moduleGraph = buildModuleGraph(index, inventory);
  const analysis = await buildRepositoryRouteFlowAnalysis(root, inventory, index, moduleGraph);

  assert.equal(analysis.routeFlows.length, 1);
  assert.equal(analysis.routeProtectionContexts.length, 1);
  const protection = analysis.routeProtectionContexts[0];
  assert.equal(protection.status, "authentication-signal-observed");
  assert.equal(protection.interpretation, "structural-auth-signals-not-protection-proof");
  assert.deepEqual(protection.evidence.map((item) => [item.kind, item.source]), [
    ["authentication", "route-registration"],
  ]);

  const sink = analysis.routeFlows[0].evidence.find((item) => item.kind === "database");
  assert.ok(sink);
  const findingContext = findingRouteProtectionEvidence(
    analysis.routeProtectionContexts,
    analysis.routeFlows,
    sink.path,
    sink.line,
  );
  assert.equal(findingContext[0]?.status, "authentication-signal-observed");
  assert.equal(JSON.stringify(findingContext).includes("select secret"), false);
  assert.equal(JSON.stringify(analysis.routeProtectionContexts).includes("select secret"), false);
});

test("composed analysis does not label an unrelated auth token elsewhere in the file as route protection", async (t) => {
  const source = [
    "const router = { get() {} };",
    "router.get('/health', health);",
    "",
    "function health() {",
    "  return db.query('select 1');",
    "}",
    "",
    "function unrelatedAdminPath() {",
    "  return isAdmin(user);",
    "}",
  ].join("\n");
  const { root, inventory } = await fixture({ "server.ts": source });
  t.after(() => rm(root, { recursive: true, force: true }));

  const index = await buildRepositoryIndex(root, inventory);
  const moduleGraph = buildModuleGraph(index, inventory);
  const analysis = await buildRepositoryRouteFlowAnalysis(root, inventory, index, moduleGraph);

  assert.equal(analysis.routeProtectionContexts.length, 1);
  assert.equal(analysis.routeProtectionContexts[0]?.status, "no-auth-signal-observed");
  assert.deepEqual(analysis.routeProtectionContexts[0]?.evidence, []);
});
