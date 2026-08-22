import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { buildCallGraph, findCallNeighborhood } from "../packages/repository/dist/call-graph.js";

async function fixture(files) {
  const root = await mkdtemp(join(tmpdir(), "synsec-call-graph-"));
  const index = [];
  for (const [path, content] of Object.entries(files)) {
    const absolute = join(root, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, content, "utf8");
    index.push({ path, size: Buffer.byteLength(content) });
  }
  return { root, index };
}

test("buildCallGraph resolves direct same-file JavaScript calls conservatively", async () => {
  const { root, index } = await fixture({
    "src/service.ts": [
      "export function validate(input: string) {",
      "  return input.length > 0;",
      "}",
      "",
      "export async function handle(input: string) {",
      "  if (!validate(input)) return false;",
      "  await externalClient.send(input);",
      "  return persist(input);",
      "}",
      "",
      "const persist = (input: string) => {",
      "  return Boolean(input);",
      "};",
    ].join("\n"),
  });

  try {
    const graph = await buildCallGraph(root, index);
    assert.equal(graph.interpretation, "lexical-call-evidence-only");
    assert.deepEqual(graph.nodes.map((node) => node.name), ["validate", "handle", "persist"]);

    const validate = graph.nodes.find((node) => node.name === "validate");
    const handle = graph.nodes.find((node) => node.name === "handle");
    const persist = graph.nodes.find((node) => node.name === "persist");
    assert.ok(validate && handle && persist);

    assert.ok(graph.edges.some((edge) => edge.from === handle.id && edge.callee === "validate" && edge.target === validate.id));
    assert.ok(graph.edges.some((edge) => edge.from === handle.id && edge.callee === "persist" && edge.target === persist.id));
    assert.ok(graph.edges.some((edge) => edge.from === handle.id && edge.callee === "externalClient.send" && edge.resolution === "external-or-unresolved"));

    const neighborhood = findCallNeighborhood(graph, handle.id, 2);
    assert.deepEqual(neighborhood.callees.map((item) => item.id).sort(), [persist.id, validate.id].sort());
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("buildCallGraph understands Python def indentation and direct calls", async () => {
  const { root, index } = await fixture({
    "app.py": [
      "def load_user(user_id):",
      "    return db.fetch(user_id)",
      "",
      "def handler(user_id):",
      "    user = load_user(user_id)",
      "    return render(user)",
      "",
      "def render(user):",
      "    return str(user)",
    ].join("\n"),
  });

  try {
    const graph = await buildCallGraph(root, index);
    const handler = graph.nodes.find((node) => node.name === "handler");
    const loadUser = graph.nodes.find((node) => node.name === "load_user");
    const render = graph.nodes.find((node) => node.name === "render");
    assert.ok(handler && loadUser && render);
    assert.ok(graph.edges.some((edge) => edge.from === handler.id && edge.target === loadUser.id));
    assert.ok(graph.edges.some((edge) => edge.from === handler.id && edge.target === render.id));
    assert.ok(graph.edges.some((edge) => edge.from === loadUser.id && edge.callee === "db.fetch" && !edge.target));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("call graph skips oversized source files rather than reading them", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-call-graph-large-"));
  try {
    const graph = await buildCallGraph(root, [{ path: "large.ts", size: 600_000 }]);
    assert.equal(graph.nodes.length, 0);
    assert.equal(graph.skippedFiles.length, 1);
    assert.match(graph.skippedFiles[0].reason, /exceeds/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
