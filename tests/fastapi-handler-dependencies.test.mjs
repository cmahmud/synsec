import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function makeRepository(filesByPath) {
  const root = await mkdtemp(join(tmpdir(), "synsec-fastapi-handler-dependencies-"));
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

test("FastAPI handler parameter Depends resolves same-file dependency with bounded auth evidence", async () => {
  const repo = await makeRepository({
    "app.py": [
      "from fastapi import FastAPI, Depends",
      "app = FastAPI()",
      "def require_user():",
      "    authentication(session)",
      '@app.get("/account")',
      "def account(user = Depends(require_user)):",
      "    return {'ok': True}",
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    assert.equal(analysis.fastApiDependencyContexts.length, 1);
    const context = analysis.fastApiDependencyContexts[0];
    assert.equal(context?.route.route, "/account");
    assert.equal(context?.handler, "account");
    assert.equal(context?.dependencies.length, 1);
    assert.equal(context?.dependencies[0]?.source, "handler-parameter");
    assert.equal(context?.dependencies[0]?.parameter, "user");
    assert.equal(context?.dependencies[0]?.name, "require_user");
    assert.equal(context?.dependencies[0]?.resolution, "same-file-function");
    assert.equal(context?.authEvidence.some((item) => item.kind === "authentication" && item.line === 4), true);
    assert.equal(context?.interpretation, "structural-fastapi-dependency-evidence-not-runtime-protection");
  } finally {
    await repo.cleanup();
  }
});

test("FastAPI handler parameter Security resolves repository-local aliased import", async () => {
  const repo = await makeRepository({
    "web/__init__.py": "",
    "web/app.py": [
      "from fastapi import FastAPI, Security",
      "from .auth import require_admin as admin_guard",
      "app = FastAPI()",
      '@app.get("/admin")',
      "def admin(user: object = Security(admin_guard)):",
      "    return True",
    ].join("\n"),
    "web/auth.py": [
      "def require_admin():",
      "    authorize(current_user)",
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    const dependency = analysis.fastApiDependencyContexts[0]?.dependencies[0];
    assert.equal(dependency?.source, "handler-parameter");
    assert.equal(dependency?.wrapper, "Security");
    assert.equal(dependency?.resolution, "imported-named-function");
    assert.equal(dependency?.node?.path, "web/auth.py");
    assert.equal(analysis.fastApiDependencyContexts[0]?.authEvidence.some((item) => item.kind === "authorization"), true);
  } finally {
    await repo.cleanup();
  }
});

test("FastAPI route-list and handler-parameter dependencies remain independently identified", async () => {
  const repo = await makeRepository({
    "app.py": [
      "from fastapi import FastAPI, Depends, Security",
      "app = FastAPI()",
      "def rate_limit():",
      "    authentication(token)",
      "def require_admin():",
      "    authorize(current_user)",
      '@app.get("/admin", dependencies=[Depends(rate_limit)])',
      "def admin(user = Security(require_admin)):",
      "    return True",
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    const dependencies = analysis.fastApiDependencyContexts[0]?.dependencies ?? [];
    assert.deepEqual(dependencies.map(({ name, source }) => ({ name, source })), [
      { name: "rate_limit", source: "route-list" },
      { name: "require_admin", source: "handler-parameter" },
    ]);
  } finally {
    await repo.cleanup();
  }
});

test("FastAPI handler dependency factories fail closed", async () => {
  const repo = await makeRepository({
    "app.py": [
      "from fastapi import FastAPI, Depends",
      "app = FastAPI()",
      "def dependency_factory():",
      "    return lambda: True",
      '@app.get("/dynamic")',
      "def dynamic_route(user = Depends(dependency_factory())):",
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

test("FastAPI multiline handler dependency signatures are omitted rather than guessed", async () => {
  const repo = await makeRepository({
    "app.py": [
      "from fastapi import FastAPI, Depends",
      "app = FastAPI()",
      "def require_user():",
      "    authentication(session)",
      '@app.get("/account")',
      "def account(",
      "    user = Depends(require_user),",
      "):",
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

test("FastAPI handler dependency import shadowing before the signature remains unresolved", async () => {
  const repo = await makeRepository({
    "web/__init__.py": "",
    "web/app.py": [
      "from fastapi import FastAPI, Depends",
      "from .auth import require_user",
      "require_user = replacement",
      "app = FastAPI()",
      '@app.get("/account")',
      "def account(user = Depends(require_user)):",
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
  } finally {
    await repo.cleanup();
  }
});
