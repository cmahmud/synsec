import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function makeRepository(filesByPath) {
  const root = await mkdtemp(join(tmpdir(), "synsec-express-router-flow-"));
  const files = [];
  for (const [path, content] of Object.entries(filesByPath)) {
    const absolute = join(root, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, content, "utf8");
    files.push({ path, size: Buffer.byteLength(content) });
  }
  return { root, files, cleanup: () => rm(root, { recursive: true, force: true }) };
}

test("mounted Express routes participate in exact sink correlation", async () => {
  const repo = await makeRepository({
    "app.js": ['import express from "express";', 'import adminRouter from "./admin.js";', "const app = express();", 'app.use("/api", adminRouter);'].join("\n"),
    "admin.js": ['import express from "express";', "const router = express.Router();", 'router.post("/admin/run", runAdmin);', "function runAdmin(req, res) {", "  child_process.exec(command);", "}", "export default router;"].join("\n"),
  });
  try {
    const index = await buildRepositoryIndex(repo.root, repo.files);
    const analysis = await buildRepositoryRouteFlowAnalysis(repo.root, repo.files, index, buildModuleGraph(index, repo.files));
    const route = analysis.entrypoints.find((entrypoint) => entrypoint.route.frameworkHint === "Express composed router");
    assert.equal(route?.route.route, "/api/admin/run");
    assert.equal(
      analysis.routeFlows.some((flow) => flow.route.route === "/api/admin/run" && flow.evidence.some((item) => item.path === "admin.js" && item.line === 5 && item.kind === "process")),
      true,
    );
  } finally {
    await repo.cleanup();
  }
});
