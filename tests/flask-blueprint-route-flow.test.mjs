import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function makeRepository(filesByPath) {
  const root = await mkdtemp(join(tmpdir(), "synsec-flask-route-flow-"));
  const files = [];
  for (const [path, content] of Object.entries(filesByPath)) {
    const absolute = join(root, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, content, "utf8");
    files.push({ path, size: Buffer.byteLength(content) });
  }
  return { root, files, cleanup: () => rm(root, { recursive: true, force: true }) };
}

test("aggregate route-flow analysis carries composed Flask Blueprint routes into exact sink correlation", async () => {
  const repo = await makeRepository({
    "web/__init__.py": "",
    "web/app.py": [
      "from flask import Flask",
      "from .admin import admin",
      "app = Flask(__name__)",
      'app.register_blueprint(admin, url_prefix="/api")',
    ].join("\n"),
    "web/admin.py": [
      "from flask import Blueprint",
      'admin = Blueprint("admin", __name__, url_prefix="/admin")',
      '@admin.post("/jobs")',
      "def create_job():",
      "    cursor.execute(statement)",
    ].join("\n"),
  });
  try {
    const index = await buildRepositoryIndex(repo.root, repo.files);
    const analysis = await buildRepositoryRouteFlowAnalysis(
      repo.root,
      repo.files,
      index,
      buildModuleGraph(index, repo.files),
    );
    const route = analysis.entrypoints.find((entrypoint) => entrypoint.route.route === "/api/admin/jobs");
    assert.equal(route?.route.frameworkHint, "Flask composed blueprint");
    assert.equal(
      analysis.routeFlows.some((flow) => (
        flow.route.route === "/api/admin/jobs"
        && flow.evidence.some((item) => item.path === "web/admin.py" && item.line === 5)
      )),
      true,
    );
  } finally {
    await repo.cleanup();
  }
});
