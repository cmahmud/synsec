import assert from "node:assert/strict";
import test from "node:test";
import { chmod, mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { TrivyAdapter, normalizeTrivyChangedFiles } from "../packages/scanners/dist/trivy.js";

test("Trivy changed-file paths are bounded, deduplicated, and repository-relative", () => {
  assert.deepEqual(normalizeTrivyChangedFiles(["./src/a.ts", "src/a.ts", "src/b.ts"]), ["src/a.ts", "src/b.ts"]);
  assert.deepEqual(normalizeTrivyChangedFiles([]), []);
  assert.equal(normalizeTrivyChangedFiles(undefined), undefined);
  for (const unsafe of ["../outside", "src/../../outside", "/tmp/outside", "C:/outside", "bad\0name"]) {
    assert.throws(() => normalizeTrivyChangedFiles([unsafe]), /unsafe repository path/);
  }
  assert.throws(
    () => normalizeTrivyChangedFiles(Array.from({ length: 501 }, (_, index) => `src/${index}.ts`)),
    /500-file adapter limit/,
  );
});

test("Trivy incremental scan stages only changed files and preserves repository-local config cwd", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-trivy-root-"));
  const bin = await mkdtemp(join(tmpdir(), "synsec-trivy-bin-"));
  const previousPath = process.env.PATH;
  try {
    await mkdir(join(root, "src"), { recursive: true });
    await writeFile(join(root, "src/a.ts"), "const token = 'fixture';\n", "utf8");
    await writeFile(join(root, "src/b.ts"), "const other = 'fixture';\n", "utf8");
    await writeFile(join(root, "unrelated.txt"), "must not be staged\n", "utf8");
    await writeFile(join(root, "trivy-secret.yaml"), "rules: []\n", "utf8");

    const fake = join(bin, "trivy");
    await writeFile(fake, `#!/usr/bin/env node
import { access } from "node:fs/promises";
import { join, resolve } from "node:path";
const args = process.argv.slice(2);
if (args[0] !== "fs") process.exit(30);
if (resolve(process.cwd()) !== resolve(${JSON.stringify(root)})) process.exit(31);
await access(join(process.cwd(), "trivy-secret.yaml"));
const target = args.at(-1);
await access(join(target, "src/a.ts"));
await access(join(target, "src/b.ts"));
try { await access(join(target, "unrelated.txt")); process.exit(32); } catch {}
console.log(JSON.stringify({ Results: [{
  Target: join(target, "src/a.ts"),
  Secrets: [{ RuleID: "fixture-secret", Title: "Fixture secret", Severity: "HIGH", StartLine: 1 }]
}] }));
`, "utf8");
    await chmod(fake, 0o755);
    process.env.PATH = `${bin}${delimiter}${previousPath ?? ""}`;

    const result = await new TrivyAdapter().scan({
      target: { path: root },
      changedFiles: ["src/a.ts", "src/b.ts"],
      timeoutMs: 10_000,
    });
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].location?.path, "src/a.ts");
    assert.match(result.diagnostics.join("\n"), /scanned 2 staged changed file/);
  } finally {
    process.env.PATH = previousPath;
    await rm(root, { recursive: true, force: true });
    await rm(bin, { recursive: true, force: true });
  }
});

test("Trivy incremental scan falls back to full repository scope for symlink ambiguity", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-trivy-fallback-root-"));
  const outside = await mkdtemp(join(tmpdir(), "synsec-trivy-outside-"));
  const bin = await mkdtemp(join(tmpdir(), "synsec-trivy-fallback-bin-"));
  const previousPath = process.env.PATH;
  try {
    await writeFile(join(outside, "secret.txt"), "fixture\n", "utf8");
    await symlink(join(outside, "secret.txt"), join(root, "linked.txt"));

    const fake = join(bin, "trivy");
    await writeFile(fake, `#!/usr/bin/env node
import { resolve } from "node:path";
const args = process.argv.slice(2);
const target = args.at(-1);
if (resolve(target) !== resolve(${JSON.stringify(root)})) process.exit(33);
console.log(JSON.stringify({ Results: [] }));
`, "utf8");
    await chmod(fake, 0o755);
    process.env.PATH = `${bin}${delimiter}${previousPath ?? ""}`;

    const result = await new TrivyAdapter().scan({
      target: { path: root },
      changedFiles: ["linked.txt"],
      timeoutMs: 10_000,
    });
    assert.deepEqual(result.findings, []);
    assert.match(result.diagnostics.join("\n"), /fell back to a full repository scan/);
  } finally {
    process.env.PATH = previousPath;
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
    await rm(bin, { recursive: true, force: true });
  }
});
