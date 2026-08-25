import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function makeRepository(filesByPath) {
  const root = await mkdtemp(join(tmpdir(), "synsec-fastapi-dependencies-"));
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

test("FastAPI route dependencies resolve same-file functions and bounded auth evidence", async () => {
  const repo = await makeRepository({
    "app.py": [
      "from fastapi import FastAPI, Depends",
      "app = FastAPI()",
      "",
      "def require_admin():",
      "    authorize(current_user)",
      "",
      '@app.get("/admin", dependencies=[Depends(require_admin)])',
      "def admin_panel():",
      "    cursor.execute(query_text)",
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    assert.equal(analysis.fastApiDependencyContexts.length, 1);
    const context = analysis.fastApiDependencyContexts[0];
    assert.equal(context?.route.frameworkHint, "FastAPI route decorator");
    assert.equal(context?.route.route, "/admin");
    assert.equal(context?.dependencies[0]?.name, "require_admin");
    assert.equal(context?.dependencies[0]?.wrapper, "Depends");
    assert.equal(context?.dependencies[0]?.resolution, "same-file-function");
    assert.deepEqual(context?.authEvidence.map(({ path, line, kind, dependency, depth }) => ({
      path, line, kind, dependency, depth,
    })), [{
      path: "app.py",
      line: 5,
      kind: "authorization",
      dependency: "require_admin",
      depth: 0,
    }]);
    assert.equal(context?.status, "auth-signal-observed");
    assert.equal(context?.interpretation, "structural-fastapi-dependency-evidence-not-runtime-protection");
  } finally {
    await repo.cleanup();
  }
});

test("FastAPI route dependencies resolve repository-local named imports and helper calls", async () => {
  const repo = await makeRepository({
    "web/__init__.py": "",
    "web/app.py": [
      "from fastapi import FastAPI, Security",
      "from .auth import require_user as current_user_dependency",
      "app = FastAPI()",
      '@app.get("/account", dependencies=[Security(current_user_dependency)])',
      "def account():",
      "    return {'ok': True}",
    ].join("\n"),
    "web/auth.py": [
      "def require_user():",
      "    verify_session()",
      "",
      "def verify_session():",
      "    authentication(session)",
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    const context = analysis.fastApiDependencyContexts[0];
    assert.equal(context?.dependencies[0]?.resolution, "imported-named-function");
    assert.equal(context?.dependencies[0]?.node?.path, "web/auth.py");
    assert.equal(context?.callScope, "dependency-and-bounded-callees");
    assert.equal(context?.authEvidence.some((item) => (
      item.path === "web/auth.py" && item.line === 5 && item.depth === 1 && item.kind === "authentication"
    )), true);
  } finally {
    await repo.cleanup();
  }
});

test("FastAPI dynamic dependency factories fail closed instead of producing structural context", async () => {
  const repo = await makeRepository({
    "app.py": [
      "from fastapi import FastAPI, Depends",
      "app = FastAPI()",
      "def dependency_factory():",
      "    return lambda: True",
      '@app.get("/dynamic", dependencies=[Depends(dependency_factory())])',
      "def dynamic_route():",
      "    return True",
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    assert.deepEqual(analysis.fastApiDependencyContexts, []);
  } finally {
    await repo.cleanup();
  }
});

test("FastAPI shadowed imported dependencies remain unresolved and do not manufacture auth evidence", async () => {
  const repo = await makeRepository({
    "web/__init__.py": "",
    "web/app.py": [
      "from fastapi import FastAPI, Depends",
      "from .auth import require_user",
      "require_user = replacement",
      "app = FastAPI()",
      '@app.get("/account", dependencies=[Depends(require_user)])',
      "def account():",
      "    return True",
    ].join("\n"),
    "web/auth.py": [
      "def require_user():",
      "    authentication(session)",
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    const context = analysis.fastApiDependencyContexts[0];
    assert.equal(context?.dependencies[0]?.resolution, "unresolved");
    assert.deepEqual(context?.authEvidence, []);
    assert.equal(context?.status, "no-auth-signal-observed");
  } finally {
    await repo.cleanup();
  }
});

test("FastAPI dependency wrappers must themselves be explicit unshadowed FastAPI imports", async () => {
  const repo = await makeRepository({
    "app.py": [
      "from fastapi import FastAPI, Depends",
      "Depends = custom_wrapper",
      "app = FastAPI()",
      "def require_user():",
      "    authentication(session)",
      '@app.get("/account", dependencies=[Depends(require_user)])',
      "def account():",
      "    return True",
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    assert.deepEqual(analysis.fastApiDependencyContexts, []);
  } finally {
    await repo.cleanup();
  }
});
