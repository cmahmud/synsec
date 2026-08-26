import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getFindingContext, inventoryRepository } from "../packages/repository/dist/index.js";

test("repository inventory detects languages and frameworks", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-repo-test-"));
  try {
    await mkdir(join(root, "src"));
    await writeFile(join(root, "package.json"), JSON.stringify({ dependencies: { express: "^5.0.0" }, devDependencies: { typescript: "^5.0.0" } }));
    await writeFile(join(root, "src", "app.ts"), "const x = 1;\nconsole.log(x);\n");
    const inventory = await inventoryRepository(root);
    assert.equal(inventory.metadata.languages.TypeScript, 1);
    assert.ok(inventory.metadata.frameworks.includes("Express"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("finding context refuses traversal and returns bounded excerpts", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-context-test-"));
  try {
    await mkdir(join(root, "src"));
    await writeFile(join(root, "src", "app.js"), "one\ntwo\nthree\nfour\nfive\n");
    const context = await getFindingContext(root, {
      id: "1",
      title: "fixture",
      category: "sast",
      severity: "medium",
      confidence: 0.8,
      scanner: { name: "fixture" },
      location: { path: "src/app.js", startLine: 3 },
    }, 1);
    assert.equal(context.startLine, 2);
    assert.equal(context.endLine, 4);
    assert.match(context.excerpt, /three/);

    const escaped = await getFindingContext(root, {
      id: "2",
      title: "fixture",
      category: "sast",
      severity: "medium",
      confidence: 0.8,
      scanner: { name: "fixture" },
      location: { path: "../outside.txt", startLine: 1 },
    });
    assert.equal(escaped, undefined);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
