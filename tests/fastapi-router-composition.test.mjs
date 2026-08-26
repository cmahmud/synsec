import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { buildRepositoryRouteFlowAnalysis } from "@synsec/repository/route-flow-analysis";

async function makeRepository(filesByPath) {
  const root = await mkdtemp(join(tmpdir(), "synsec-fastapi-router-composition-"));
  const files = [];
  for (const [path, content] of Object.entries(filesByPath)) {
    const absolute = join(root, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, content, "utf8");
    files.push({ path, size: Buffer.byteLength(content) });
  }
  return { root, files, cleanup: () => rm(root, { recursive: true, force: true }) };
}

async function analyze(repo, options) {
  const index = await buildRepositoryIndex(repo.root, repo.files);
  return buildRepositoryRouteFlowAnalysis(
    repo.root,
    repo.files,
    index,
    buildModuleGraph(index, repo.files),
    options,
  );
}

function composedEntrypoints(analysis) {
  return analysis.entrypoints.filter((entrypoint) => entrypoint.route.frameworkHint === "FastAPI composed router");
}

test("FastAPI imported APIRouter prefixes compose into exact route and sink evidence", async () => {
  const repo = await makeRepository({
    "api/__init__.py": "",
    "api/app.py": [
      "from fastapi import FastAPI",
      "from .users import router as users_router",
      "app = FastAPI()",
      'app.include_router(users_router, prefix="/api")',
    ].join("\n"),
    "api/users.py": [
      "from fastapi import APIRouter",
      'router = APIRouter(prefix="/users")',
      '@router.get("/{user_id}")',
      "def get_user(user_id):",
      "    cursor.execute(query_text)",
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    const composed = composedEntrypoints(analysis);
    assert.equal(composed.length, 1);
    assert.equal(composed[0]?.route.route, "/api/users/{user_id}");
    assert.equal(composed[0]?.handler?.path, "api/users.py");
    assert.equal(composed[0]?.compositionInterpretation, "structural-fastapi-router-composition-not-runtime-reachability");
    assert.equal(
      analysis.routeFlows.some((flow) => (
        flow.route.route === "/api/users/{user_id}"
        && flow.evidence.some((item) => item.path === "api/users.py" && item.line === 5)
      )),
      true,
    );
  } finally {
    await repo.cleanup();
  }
});

test("FastAPI nested router includes compose bounded parent, include, and child prefixes", async () => {
  const repo = await makeRepository({
    "api/__init__.py": "",
    "api/app.py": [
      "from fastapi import FastAPI",
      "from .v1 import router as v1_router",
      "app = FastAPI()",
      'app.include_router(v1_router, prefix="/api")',
    ].join("\n"),
    "api/v1.py": [
      "from fastapi import APIRouter",
      "from .users import router as users_router",
      'router = APIRouter(prefix="/v1")',
      'router.include_router(users_router, prefix="/accounts")',
    ].join("\n"),
    "api/users.py": [
      "from fastapi import APIRouter",
      'router = APIRouter(prefix="/users")',
      '@router.post("/")',
      "def create_user():",
      "    database.save(record)",
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    const composed = composedEntrypoints(analysis);
    assert.equal(composed.length, 1);
    assert.equal(composed[0]?.route.route, "/api/v1/accounts/users");
    assert.equal(composed[0]?.composition?.includeDepth, 2);
    assert.deepEqual(composed[0]?.composition?.prefixes, ["/api", "/v1", "/accounts", "/users"]);
  } finally {
    await repo.cleanup();
  }
});

test("FastAPI dynamic include prefixes fail closed", async () => {
  const repo = await makeRepository({
    "api/__init__.py": "",
    "api/app.py": [
      "from fastapi import FastAPI",
      "from .users import router as users_router",
      "app = FastAPI()",
      'API_PREFIX = "/api"',
      "app.include_router(users_router, prefix=API_PREFIX)",
    ].join("\n"),
    "api/users.py": [
      "from fastapi import APIRouter",
      "router = APIRouter()",
      '@router.get("/users")',
      "def users():",
      "    return True",
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    assert.deepEqual(composedEntrypoints(analysis), []);
  } finally {
    await repo.cleanup();
  }
});

test("FastAPI shadowed imported router bindings fail closed", async () => {
  const repo = await makeRepository({
    "api/__init__.py": "",
    "api/app.py": [
      "from fastapi import FastAPI",
      "from .users import router as users_router",
      "app = FastAPI()",
      "users_router = make_router()",
      'app.include_router(users_router, prefix="/api")',
    ].join("\n"),
    "api/users.py": [
      "from fastapi import APIRouter",
      "router = APIRouter()",
      '@router.get("/users")',
      "def users():",
      "    return True",
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    assert.deepEqual(composedEntrypoints(analysis), []);
  } finally {
    await repo.cleanup();
  }
});

test("FastAPI router composition obeys include-depth bounds without widening evidence", async () => {
  const repo = await makeRepository({
    "api/__init__.py": "",
    "api/app.py": [
      "from fastapi import FastAPI",
      "from .v1 import router as v1_router",
      "app = FastAPI()",
      "app.include_router(v1_router)",
    ].join("\n"),
    "api/v1.py": [
      "from fastapi import APIRouter",
      "from .users import router as users_router",
      "router = APIRouter()",
      "router.include_router(users_router)",
    ].join("\n"),
    "api/users.py": [
      "from fastapi import APIRouter",
      "router = APIRouter()",
      '@router.get("/users")',
      "def users():",
      "    return True",
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo, { maxFastApiIncludeDepth: 1 });
    assert.deepEqual(composedEntrypoints(analysis), []);
  } finally {
    await repo.cleanup();
  }
});

test("FastAPI router declarations used before definition do not create composed evidence", async () => {
  const repo = await makeRepository({
    "app.py": [
      "from fastapi import FastAPI, APIRouter",
      "app = FastAPI()",
      'app.include_router(router, prefix="/api")',
      "router = APIRouter()",
      '@router.get("/late")',
      "def late():",
      "    return True",
    ].join("\n"),
  });
  try {
    const analysis = await analyze(repo);
    assert.deepEqual(composedEntrypoints(analysis), []);
  } finally {
    await repo.cleanup();
  }
});
