import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "@synsec/repository/analysis";
import { buildCallGraph } from "@synsec/repository/call-graph";
import { composeFlaskBlueprintEntrypoints } from "@synsec/repository/flask-blueprint-composition";
import { buildModuleGraph } from "@synsec/repository/module-graph";
import { repositoryRouteSinkFlowContexts } from "@synsec/repository/route-sink-flow";

async function makeRepository(filesByPath) {
  const root = await mkdtemp(join(tmpdir(), "synsec-flask-blueprint-composition-"));
  const files = [];
  for (const [path, content] of Object.entries(filesByPath)) {
    const absolute = join(root, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, content, "utf8");
    files.push({ path, size: Buffer.byteLength(content) });
  }
  return { root, files, cleanup: () => rm(root, { recursive: true, force: true }) };
}

async function compose(repo, options) {
  const index = await buildRepositoryIndex(repo.root, repo.files);
  const moduleGraph = buildModuleGraph(index, repo.files);
  const entrypoints = await composeFlaskBlueprintEntrypoints(repo.root, repo.files, moduleGraph, [], options);
  const callGraph = await buildCallGraph(repo.root, repo.files);
  return {
    index,
    entrypoints,
    routeFlows: repositoryRouteSinkFlowContexts(index, entrypoints, callGraph),
  };
}

function flaskEntrypoints(result) {
  return result.entrypoints.filter((entrypoint) => entrypoint.route.frameworkHint === "Flask composed blueprint");
}

test("Flask imported Blueprint prefixes compose into exact route and sink evidence", async () => {
  const repo = await makeRepository({
    "app/__init__.py": "",
    "app/main.py": [
      "from flask import Flask",
      "from .users import users as users_blueprint",
      "app = Flask(__name__)",
      'app.register_blueprint(users_blueprint, url_prefix="/api")',
    ].join("\n"),
    "app/users.py": [
      "from flask import Blueprint",
      'users = Blueprint("users", __name__, url_prefix="/users")',
      '@users.get("/<user_id>")',
      "def get_user(user_id):",
      "    cursor.execute(query_text)",
    ].join("\n"),
  });
  try {
    const result = await compose(repo);
    const entrypoints = flaskEntrypoints(result);
    assert.equal(entrypoints.length, 1);
    assert.equal(entrypoints[0]?.route.route, "/api/users/<user_id>");
    assert.equal(entrypoints[0]?.handler?.path, "app/users.py");
    assert.equal(
      entrypoints[0]?.compositionInterpretation,
      "structural-flask-blueprint-composition-not-runtime-reachability",
    );
    assert.equal(
      result.routeFlows.some((flow) => (
        flow.route.route === "/api/users/<user_id>"
        && flow.evidence.some((item) => item.path === "app/users.py" && item.line === 5)
      )),
      true,
    );
  } finally {
    await repo.cleanup();
  }
});

test("Flask nested Blueprint registration composes parent, registration, and child prefixes", async () => {
  const repo = await makeRepository({
    "app/__init__.py": "",
    "app/main.py": [
      "from flask import Flask",
      "from .api import api",
      "app = Flask(__name__)",
      'app.register_blueprint(api, url_prefix="/root")',
    ].join("\n"),
    "app/api.py": [
      "from flask import Blueprint",
      "from .users import users",
      'api = Blueprint("api", __name__, url_prefix="/v1")',
      'api.register_blueprint(users, url_prefix="/accounts")',
    ].join("\n"),
    "app/users.py": [
      "from flask import Blueprint",
      'users = Blueprint("users", __name__, url_prefix="/users")',
      '@users.post("/")',
      "def create_user():",
      "    database.execute(statement)",
    ].join("\n"),
  });
  try {
    const result = await compose(repo);
    const entrypoint = flaskEntrypoints(result)[0];
    assert.equal(entrypoint?.route.route, "/root/v1/accounts/users");
    assert.equal(entrypoint?.composition?.registerDepth, 2);
    assert.deepEqual(entrypoint?.composition?.prefixes, ["/root", "/v1", "/accounts", "/users"]);
  } finally {
    await repo.cleanup();
  }
});

test("Flask dynamic registration prefixes fail closed", async () => {
  const repo = await makeRepository({
    "app/__init__.py": "",
    "app/main.py": [
      "from flask import Flask",
      "from .users import users",
      "app = Flask(__name__)",
      'API_PREFIX = "/api"',
      "app.register_blueprint(users, url_prefix=API_PREFIX)",
    ].join("\n"),
    "app/users.py": [
      "from flask import Blueprint",
      'users = Blueprint("users", __name__)',
      '@users.get("/users")',
      "def list_users():",
      "    return True",
    ].join("\n"),
  });
  try {
    assert.deepEqual(flaskEntrypoints(await compose(repo)), []);
  } finally {
    await repo.cleanup();
  }
});

test("Flask shadowed imported Blueprint bindings fail closed", async () => {
  const repo = await makeRepository({
    "app/__init__.py": "",
    "app/main.py": [
      "from flask import Flask",
      "from .users import users",
      "app = Flask(__name__)",
      "users = build_blueprint()",
      'app.register_blueprint(users, url_prefix="/api")',
    ].join("\n"),
    "app/users.py": [
      "from flask import Blueprint",
      'users = Blueprint("users", __name__)',
      '@users.get("/users")',
      "def list_users():",
      "    return True",
    ].join("\n"),
  });
  try {
    assert.deepEqual(flaskEntrypoints(await compose(repo)), []);
  } finally {
    await repo.cleanup();
  }
});

test("Flask Blueprint composition obeys registration depth bounds", async () => {
  const repo = await makeRepository({
    "app/__init__.py": "",
    "app/main.py": [
      "from flask import Flask",
      "from .api import api",
      "app = Flask(__name__)",
      "app.register_blueprint(api)",
    ].join("\n"),
    "app/api.py": [
      "from flask import Blueprint",
      "from .users import users",
      'api = Blueprint("api", __name__)',
      "api.register_blueprint(users)",
    ].join("\n"),
    "app/users.py": [
      "from flask import Blueprint",
      'users = Blueprint("users", __name__)',
      '@users.get("/users")',
      "def list_users():",
      "    return True",
    ].join("\n"),
  });
  try {
    assert.deepEqual(flaskEntrypoints(await compose(repo, { maxRegisterDepth: 1 })), []);
  } finally {
    await repo.cleanup();
  }
});

test("Flask Blueprint registrations used before declaration do not create composed evidence", async () => {
  const repo = await makeRepository({
    "app.py": [
      "from flask import Flask, Blueprint",
      "app = Flask(__name__)",
      'app.register_blueprint(users, url_prefix="/api")',
      'users = Blueprint("users", __name__)',
      '@users.get("/late")',
      "def late():",
      "    return True",
    ].join("\n"),
  });
  try {
    assert.deepEqual(flaskEntrypoints(await compose(repo)), []);
  } finally {
    await repo.cleanup();
  }
});
