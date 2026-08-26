import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { buildRepositoryIndex } from "../packages/repository/dist/analysis.js";
import { buildCallGraph } from "../packages/repository/dist/call-graph.js";
import { buildImportCallLinkGraph } from "../packages/repository/dist/import-call-links.js";
import { buildModuleGraph } from "../packages/repository/dist/module-graph.js";

async function fixture(filesByPath) {
  const root = await mkdtemp(join(tmpdir(), "synsec-import-call-links-"));
  const files = [];
  for (const [path, content] of Object.entries(filesByPath)) {
    await mkdir(join(root, path, "..").replace(/[/\\][^/\\]+[/\\]\.\.$/, ""), { recursive: true }).catch(() => {});
    const absolute = join(root, path);
    await mkdir(absolute.slice(0, Math.max(absolute.lastIndexOf("/"), absolute.lastIndexOf("\\"))), { recursive: true });
    await writeFile(absolute, content, "utf8");
    files.push({ path, size: Buffer.byteLength(content) });
  }
  return { root, files, cleanup: () => rm(root, { recursive: true, force: true }) };
}

async function buildGraphs(root, files) {
  const index = await buildRepositoryIndex(root, files);
  const moduleGraph = buildModuleGraph(index, files);
  const callGraph = await buildCallGraph(root, files);
  const importCalls = await buildImportCallLinkGraph(root, files, moduleGraph, callGraph);
  return { index, moduleGraph, callGraph, importCalls };
}

test("links explicit JS named and namespace imports to unique local functions", async () => {
  const repo = await fixture({
    "src/handler.ts": [
      'import { execute as runCommand } from "./exec.js";',
      'import * as database from "./db.js";',
      "export function handler() {",
      "  runCommand();",
      "  database.queryUser();",
      "}",
    ].join("\n"),
    "src/exec.ts": "export function execute() { return 1; }\n",
    "src/db.ts": "export function queryUser() { return 2; }\n",
  });
  try {
    const { importCalls } = await buildGraphs(repo.root, repo.files);
    assert.equal(importCalls.interpretation, "cross-module-import-call-evidence-only");
    assert.equal(importCalls.linkedCallCount, 2);
    assert.deepEqual(importCalls.links.map(({ callee, targetPath, importedName, bindingKind, evidence }) => ({
      callee, targetPath, importedName, bindingKind, evidence,
    })), [
      {
        callee: "runCommand",
        targetPath: "src/exec.ts",
        importedName: "execute",
        bindingKind: "javascript-named-import",
        evidence: "explicit-import-binding-to-unique-local-function",
      },
      {
        callee: "database.queryUser",
        targetPath: "src/db.ts",
        importedName: "queryUser",
        bindingKind: "javascript-namespace-import",
        evidence: "explicit-import-binding-to-unique-local-function",
      },
    ]);
  } finally {
    await repo.cleanup();
  }
});

test("links explicit Python from-import aliases through resolved top-level packages", async () => {
  const repo = await fixture({
    "pkg/__init__.py": "",
    "pkg/service.py": "def execute():\n    return 1\n",
    "app.py": "from pkg.service import execute as run\n\ndef handler():\n    run()\n",
  });
  try {
    const { importCalls } = await buildGraphs(repo.root, repo.files);
    assert.equal(importCalls.linkedCallCount, 1);
    assert.deepEqual({
      callee: importCalls.links[0]?.callee,
      targetPath: importCalls.links[0]?.targetPath,
      importedName: importCalls.links[0]?.importedName,
      bindingKind: importCalls.links[0]?.bindingKind,
    }, {
      callee: "run",
      targetPath: "pkg/service.py",
      importedName: "execute",
      bindingKind: "python-from-import",
    });
  } finally {
    await repo.cleanup();
  }
});

test("refuses ambiguous imported bindings and ambiguous target functions", async () => {
  const repo = await fixture({
    "src/handler.ts": [
      'import { execute as run } from "./one.js";',
      'import { execute as run } from "./two.js";',
      "export function handler() {",
      "  run();",
      "}",
    ].join("\n"),
    "src/one.ts": [
      "export function execute() { return 1; }",
      "export function execute() { return 2; }",
    ].join("\n"),
    "src/two.ts": "export function execute() { return 3; }\n",
  });
  try {
    const { importCalls } = await buildGraphs(repo.root, repo.files);
    assert.equal(importCalls.linkedCallCount, 0);
    assert.deepEqual(importCalls.links, []);
  } finally {
    await repo.cleanup();
  }
});

test("does not treat default imports or unresolved external modules as cross-module evidence", async () => {
  const repo = await fixture({
    "src/handler.ts": [
      'import execute from "./exec.js";',
      'import { request } from "external-package";',
      "export function handler() {",
      "  execute();",
      "  request();",
      "}",
    ].join("\n"),
    "src/exec.ts": "export default function execute() { return 1; }\n",
  });
  try {
    const { importCalls } = await buildGraphs(repo.root, repo.files);
    assert.equal(importCalls.linkedCallCount, 0);
  } finally {
    await repo.cleanup();
  }
});

test("refuses a JS import binding shadowed inside the calling function", async () => {
  const repo = await fixture({
    "src/handler.ts": [
      'import { execute as run } from "./exec.js";',
      "export function handler() {",
      "  const run = localFactory();",
      "  run();",
      "}",
    ].join("\n"),
    "src/exec.ts": "export function execute() { return 1; }\n",
  });
  try {
    const { importCalls } = await buildGraphs(repo.root, repo.files);
    assert.equal(importCalls.linkedCallCount, 0);
    assert.deepEqual(importCalls.links, []);
  } finally {
    await repo.cleanup();
  }
});

test("refuses a Python import binding shadowed by a function parameter", async () => {
  const repo = await fixture({
    "pkg/__init__.py": "",
    "pkg/service.py": "def execute():\n    return 1\n",
    "app.py": [
      "from pkg.service import execute as run",
      "",
      "def handler(run):",
      "    run()",
    ].join("\n"),
  });
  try {
    const { importCalls } = await buildGraphs(repo.root, repo.files);
    assert.equal(importCalls.linkedCallCount, 0);
    assert.deepEqual(importCalls.links, []);
  } finally {
    await repo.cleanup();
  }
});
