import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function makeRepository(filesByPath) {
  const root = await mkdtemp(join(tmpdir(), "synsec-django-urlconf-composition-"));
  const files = [];
  for (const [path, content] of Object.entries(filesByPath)) {
    const absolute = join(root, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, content, "utf8");
    files.push({ path, size: Buffer.byteLength(content) });
  }
  return { root, files, cleanup: () => rm(root, { recursive: true, force: true }) };
}

async function analyze(repo, options = {}) {
  const index = await buildRepositoryIndex(repo.root, repo.files);
  const moduleGraph = buildModuleGraph(index, repo.files);
  return await buildRepositoryRouteFlowAnalysis(repo.root, repo.files, index, moduleGraph, options);
}

function composedFlows(analysis) {
  return analysis.routeFlows.filter((flow) => flow.route.frameworkHint === "Django URLConf include");
}

test("Django literal include prefixes compose into exact structural route-to-sink evidence", async () => {
  const repo = await makeRepository({
    "project/urls.py": 'path("api/", include("accounts.urls"))\n',
    "accounts/__init__.py": "",
    "accounts/urls.py": [
      "from .views import create_user",
      'path("users/", create_user)',
    ].join("\n"),
    "accounts/views.py": [
      "def create_user(request):",
      '    return persist(request.POST["name"])',
      "",
      "def persist(value):",
      "    cursor.execute(value)",
    ].join("\n"),
  });

  try {
    const analysis = await analyze(repo);
    const flows = composedFlows(analysis);
    assert.equal(flows.length, 1);
    assert.equal(flows[0]?.route.route, "api/users/");
    assert.equal(flows[0]?.handler.path, "accounts/views.py");
    assert.equal(flows[0]?.evidence[0]?.kind, "database");

    const requestFlows = analysis.requestInputFlows.filter(
      (flow) => flow.route.frameworkHint === "Django URLConf include" && flow.route.route === "api/users/",
    );
    assert.equal(requestFlows.length, 1);
    assert.equal(requestFlows[0]?.sourceKinds.includes("body"), true);
    assert.equal(requestFlows[0]?.sinkKinds.includes("database"), true);
  } finally {
    await repo.cleanup();
  }
});

test("Django include composition follows nested literal URLConfs with an explicit depth bound", async () => {
  const repo = await makeRepository({
    "project/urls.py": 'path("api/", include("service.urls"))\n',
    "service/__init__.py": "",
    "service/urls.py": 'path("v1/", include("service.users.urls"))\n',
    "service/users/__init__.py": "",
    "service/users/urls.py": [
      "from .views import detail",
      'path("users/", detail)',
    ].join("\n"),
    "service/users/views.py": "def detail(request):\n    cursor.execute(query_text)\n",
  });

  try {
    const full = await analyze(repo);
    assert.equal(composedFlows(full).some((flow) => flow.route.route === "api/v1/users/"), true);

    const shallow = await analyze(repo, { maxDjangoIncludeDepth: 1 });
    assert.equal(composedFlows(shallow).some((flow) => flow.route.route === "api/v1/users/"), false);
  } finally {
    await repo.cleanup();
  }
});

test("empty Django include prefixes preserve the child route identity", async () => {
  const repo = await makeRepository({
    "project/urls.py": 'path("", include("accounts.urls"))\n',
    "accounts/__init__.py": "",
    "accounts/urls.py": [
      "from .views import health",
      'path("health/", health)',
    ].join("\n"),
    "accounts/views.py": "def health(request):\n    cursor.execute(query_text)\n",
  });

  try {
    const analysis = await analyze(repo);
    assert.equal(composedFlows(analysis).some((flow) => flow.route.route === "health/"), true);
  } finally {
    await repo.cleanup();
  }
});

test("ambiguous and dynamic Django include targets fail closed", async () => {
  const repo = await makeRepository({
    "project/urls.py": [
      'path("ambiguous/", include("accounts.urls"))',
      'path("dynamic/", include(settings.ACCOUNT_URLCONF))',
    ].join("\n"),
    "accounts/__init__.py": "",
    "accounts/urls.py": [
      "from .views import health",
      'path("health/", health)',
    ].join("\n"),
    "accounts/urls/__init__.py": [
      "from ..views import health",
      'path("other/", health)',
    ].join("\n"),
    "accounts/views.py": "def health(request):\n    cursor.execute(query_text)\n",
  });

  try {
    const analysis = await analyze(repo);
    assert.deepEqual(composedFlows(analysis), []);
  } finally {
    await repo.cleanup();
  }
});

test("Django include cycles without a structural root produce no composed route evidence", async () => {
  const repo = await makeRepository({
    "a/urls.py": 'path("b/", include("b.urls"))\n',
    "b/urls.py": [
      'path("a/", include("a.urls"))',
      "def local(request):",
      "    cursor.execute(query_text)",
      'path("local/", local)',
    ].join("\n"),
  });

  try {
    const analysis = await analyze(repo);
    assert.deepEqual(composedFlows(analysis), []);
  } finally {
    await repo.cleanup();
  }
});
