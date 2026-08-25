import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function makeRepository(filesByPath) {
  const root = await mkdtemp(join(tmpdir(), "synsec-django-route-handler-"));
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
  const moduleGraph = buildModuleGraph(index, repo.files);
  return await buildRepositoryRouteFlowAnalysis(repo.root, repo.files, index, moduleGraph);
}

test("Django URLConf resolves an explicit repository-local named function view", async () => {
  const repo = await makeRepository({
    "web/__init__.py": "",
    "web/urls.py": [
      "from .views import create_user as create_user_view",
      'path("users/", create_user_view, name="create-user")',
    ].join("\n"),
    "web/views.py": [
      "def create_user(request):",
      '    return persist(request.POST["name"])',
      "",
      "def persist(value):",
      "    cursor.execute(value)",
    ].join("\n"),
  });

  try {
    const analysis = await analyze(repo);
    assert.equal(analysis.entrypoints.length, 1);
    assert.equal(analysis.entrypoints[0]?.resolution, "imported-named-function");
    assert.equal(analysis.entrypoints[0]?.handler?.path, "web/views.py");
    assert.equal(analysis.entrypoints[0]?.handler?.name, "create_user");
    assert.deepEqual(analysis.routeFlows[0]?.evidence.map(({ path, line, kind, depth }) => ({ path, line, kind, depth })), [
      { path: "web/views.py", line: 5, kind: "database", depth: 1 },
    ]);
    assert.equal(analysis.requestInputFlows[0]?.sourceKinds.includes("body"), true);
    assert.equal(analysis.requestInputFlows[0]?.sinkKinds.includes("database"), true);
    assert.equal(analysis.requestInputFlows[0]?.interpretation, "structural-request-source-call-sink-evidence-only");
  } finally {
    await repo.cleanup();
  }
});

test("Django URLConf resolves one unique same-file function view", async () => {
  const repo = await makeRepository({
    "urls.py": [
      'path("health/", health)',
      "",
      "def health(request):",
      "    cursor.execute(query_text)",
    ].join("\n"),
  });

  try {
    const analysis = await analyze(repo);
    assert.equal(analysis.entrypoints[0]?.resolution, "named-function");
    assert.equal(analysis.entrypoints[0]?.handler?.name, "health");
    assert.equal(analysis.routeFlows[0]?.evidence[0]?.kind, "database");
  } finally {
    await repo.cleanup();
  }
});

test("Django dotted and class-based view expressions remain unresolved", async () => {
  const repo = await makeRepository({
    "web/__init__.py": "",
    "web/urls.py": [
      "from . import views",
      'path("users/", views.create_user)',
      'path("admin/", AdminView.as_view())',
    ].join("\n"),
    "web/views.py": "def create_user(request):\n    cursor.execute(query_text)\n",
  });

  try {
    const analysis = await analyze(repo);
    assert.equal(analysis.entrypoints.length, 2);
    assert.deepEqual(analysis.entrypoints.map(({ resolution }) => resolution), ["unresolved", "unresolved"]);
    assert.deepEqual(analysis.routeFlows, []);
  } finally {
    await repo.cleanup();
  }
});

test("shadowed Django named imports remain unresolved", async () => {
  const repo = await makeRepository({
    "web/__init__.py": "",
    "web/urls.py": [
      "from .views import create_user",
      "create_user = wrap(create_user)",
      'path("users/", create_user)',
    ].join("\n"),
    "web/views.py": "def create_user(request):\n    cursor.execute(query_text)\n",
  });

  try {
    const analysis = await analyze(repo);
    assert.equal(analysis.entrypoints[0]?.resolution, "unresolved");
    assert.deepEqual(analysis.routeFlows, []);
  } finally {
    await repo.cleanup();
  }
});

test("ambiguous same-name Django view targets fail closed", async () => {
  const repo = await makeRepository({
    "web/__init__.py": "",
    "web/urls.py": [
      "from .views import create_user",
      'path("users/", create_user)',
      "",
      "def create_user(request):",
      "    cursor.execute(local_query)",
    ].join("\n"),
    "web/views.py": "def create_user(request):\n    cursor.execute(imported_query)\n",
  });

  try {
    const analysis = await analyze(repo);
    assert.equal(analysis.entrypoints[0]?.resolution, "unresolved");
    assert.deepEqual(analysis.routeFlows, []);
  } finally {
    await repo.cleanup();
  }
});
