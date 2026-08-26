import assert from "node:assert/strict";
import test from "node:test";
import { chmod, mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { GitleaksAdapter, normalizeGitleaksChangedFiles } from "../packages/scanners/dist/gitleaks.js";

test("Gitleaks changed-file paths are bounded, deduplicated, and repository-relative", () => {
  assert.deepEqual(normalizeGitleaksChangedFiles(["./src/a.ts", "src/a.ts", "src/b.ts"]), ["src/a.ts", "src/b.ts"]);
  assert.deepEqual(normalizeGitleaksChangedFiles([]), []);
  assert.equal(normalizeGitleaksChangedFiles(undefined), undefined);
  for (const unsafe of ["../outside", "src/../../outside", "/tmp/outside", "C:/outside", "bad\0name"]) {
    assert.throws(() => normalizeGitleaksChangedFiles([unsafe]), /unsafe repository path/);
  }
  assert.throws(
    () => normalizeGitleaksChangedFiles(Array.from({ length: 501 }, (_, index) => `src/${index}.ts`)),
    /500-file adapter limit/,
  );
});

test("Gitleaks incremental scan stages only changed regular files and preserves repository-relative findings", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-gitleaks-root-"));
  const bin = await mkdtemp(join(tmpdir(), "synsec-gitleaks-bin-"));
  const previousPath = process.env.PATH;
  try {
    await mkdir(join(root, "src"), { recursive: true });
    await writeFile(join(root, "src/a.ts"), "const token = 'fixture';\n", "utf8");
    await writeFile(join(root, "src/b.ts"), "const other = 'fixture';\n", "utf8");
    await writeFile(join(root, "unrelated.txt"), "must not be staged\n", "utf8");
    await writeFile(join(root, ".gitleaks.toml"), "title = 'fixture'\n", "utf8");

    const fake = join(bin, "gitleaks");
    await writeFile(fake, `#!/usr/bin/env node
import { access, writeFile } from "node:fs/promises";
import { join } from "node:path";
const args = process.argv.slice(2);
if (args[0] !== "dir") process.exit(20);
const reportIndex = args.indexOf("--report-path");
const report = args[reportIndex + 1];
const target = args.at(-1);
await access(join(target, "src/a.ts"));
await access(join(target, "src/b.ts"));
await access(join(target, ".gitleaks.toml"));
try { await access(join(target, "unrelated.txt")); process.exit(21); } catch {}
await writeFile(report, JSON.stringify([{
  RuleID: "fixture-secret",
  Description: "Fixture secret",
  File: join(target, "src/a.ts"),
  StartLine: 1,
  Fingerprint: "fixture-fingerprint"
}]));
`, "utf8");
    await chmod(fake, 0o755);
    process.env.PATH = `${bin}${delimiter}${previousPath ?? ""}`;

    const result = await new GitleaksAdapter().scan({
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

test("Gitleaks incremental scan falls back to full repository scope for symlink ambiguity", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-gitleaks-fallback-root-"));
  const outside = await mkdtemp(join(tmpdir(), "synsec-gitleaks-outside-"));
  const bin = await mkdtemp(join(tmpdir(), "synsec-gitleaks-fallback-bin-"));
  const previousPath = process.env.PATH;
  try {
    await writeFile(join(outside, "secret.txt"), "fixture\n", "utf8");
    await symlink(join(outside, "secret.txt"), join(root, "linked.txt"));

    const fake = join(bin, "gitleaks");
    await writeFile(fake, `#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
const args = process.argv.slice(2);
const report = args[args.indexOf("--report-path") + 1];
const target = args.at(-1);
if (resolve(target) !== resolve(${JSON.stringify(root)})) process.exit(22);
await writeFile(report, "[]");
`, "utf8");
    await chmod(fake, 0o755);
    process.env.PATH = `${bin}${delimiter}${previousPath ?? ""}`;

    const result = await new GitleaksAdapter().scan({
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
