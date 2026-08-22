import test from "node:test";
import assert from "node:assert/strict";
import { findLikelyTestOwners } from "@synsec/repository/test-ownership";

function graph(edges) {
  return {
    schemaVersion: 1,
    nodes: [],
    edges,
    resolvedEdgeCount: edges.filter((edge) => edge.target).length,
    unresolvedEdgeCount: edges.filter((edge) => !edge.target).length,
  };
}

test("test ownership prioritizes direct importing tests and preserves conservative interpretation", () => {
  const files = [
    { path: "src/auth.ts", content: "export const auth = true" },
    { path: "tests/auth.test.ts", content: "import '../src/auth.js'" },
    { path: "src/__tests__/auth.spec.ts", content: "" },
    { path: "tests/other.test.ts", content: "" },
  ];
  const moduleGraph = graph([
    {
      from: "tests/auth.test.ts",
      specifier: "../src/auth.js",
      kind: "import",
      target: "src/auth.ts",
      resolution: "repository-file",
    },
  ]);

  const context = findLikelyTestOwners(moduleGraph, files, "./src/auth.ts");

  assert.equal(context.interpretation, "likely-test-ownership-only");
  assert.equal(context.sourcePath, "src/auth.ts");
  assert.deepEqual(context.likelyTests, [
    { path: "tests/auth.test.ts", reasons: ["direct-import", "filename-convention"] },
    { path: "src/__tests__/auth.spec.ts", reasons: ["filename-convention"] },
  ]);
});

test("test ownership ignores non-test dependents and unrelated same-directory files", () => {
  const files = [
    { path: "src/parser.py", content: "" },
    { path: "src/consumer.py", content: "" },
    { path: "tests/test_parser.py", content: "" },
    { path: "tests/parser_fixture.py", content: "" },
  ];
  const moduleGraph = graph([
    {
      from: "src/consumer.py",
      specifier: ".parser",
      kind: "python-import",
      target: "src/parser.py",
      resolution: "repository-file",
    },
  ]);

  const context = findLikelyTestOwners(moduleGraph, files, "src/parser.py");
  assert.deepEqual(context.likelyTests, [
    { path: "tests/test_parser.py", reasons: ["filename-convention"] },
  ]);
});

test("test ownership is bounded and can explicitly return no candidates", () => {
  const files = [
    { path: "src/a.ts", content: "" },
    { path: "tests/a.test.ts", content: "" },
  ];
  const context = findLikelyTestOwners(graph([]), files, "src/a.ts", { maxResults: 0 });

  assert.equal(context.maxResults, 0);
  assert.deepEqual(context.likelyTests, []);
});

test("test ownership caps excessive result requests", () => {
  const files = [{ path: "src/a.ts", content: "" }];
  for (let index = 0; index < 150; index += 1) {
    files.push({ path: `tests/group-${index}/a.test.ts`, content: "" });
  }

  const context = findLikelyTestOwners(graph([]), files, "src/a.ts", { maxResults: 1000 });
  assert.equal(context.maxResults, 100);
  assert.equal(context.likelyTests.length, 100);
});
