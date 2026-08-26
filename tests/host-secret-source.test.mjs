import assert from "node:assert/strict";
import { mkdtemp, writeFile, symlink, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { secretValueFromEnvironmentOrFile } from "../scripts/host-secret-source.mjs";

test("host secret source accepts a direct bounded environment value", async () => {
  const value = await secretValueFromEnvironmentOrFile(
    { SYNSEC_POSTGRES_URL: "postgresql://user:pass@db/synsec" },
    "SYNSEC_POSTGRES_URL",
    "PostgreSQL credential",
  );
  assert.equal(value, "postgresql://user:pass@db/synsec");
});

test("host secret source reads one bounded absolute regular file and strips one terminal newline", async () => {
  const directory = await mkdtemp(join(tmpdir(), "synsec-secret-"));
  try {
    const path = join(directory, "postgres.url");
    await writeFile(path, "postgresql://user:pass@db/synsec\n", { mode: 0o600 });
    const value = await secretValueFromEnvironmentOrFile(
      { SYNSEC_POSTGRES_URL_FILE: path },
      "SYNSEC_POSTGRES_URL",
      "PostgreSQL credential",
    );
    assert.equal(value, "postgresql://user:pass@db/synsec");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("host secret source fails closed when direct and file modes are both supplied", async () => {
  await assert.rejects(
    secretValueFromEnvironmentOrFile(
      { SYNSEC_POSTGRES_URL: "postgresql://direct/db", SYNSEC_POSTGRES_URL_FILE: "/run/credentials/postgres.url" },
      "SYNSEC_POSTGRES_URL",
      "PostgreSQL credential",
    ),
    /exactly one/,
  );
});

test("host secret source rejects relative paths and symlinks", async () => {
  await assert.rejects(
    secretValueFromEnvironmentOrFile(
      { SYNSEC_POSTGRES_URL_FILE: "postgres.url" },
      "SYNSEC_POSTGRES_URL",
      "PostgreSQL credential",
    ),
    /absolute/,
  );

  const directory = await mkdtemp(join(tmpdir(), "synsec-secret-"));
  try {
    const target = join(directory, "target");
    const link = join(directory, "link");
    await writeFile(target, "postgresql://user:pass@db/synsec", { mode: 0o600 });
    await symlink(target, link);
    await assert.rejects(
      secretValueFromEnvironmentOrFile(
        { SYNSEC_POSTGRES_URL_FILE: link },
        "SYNSEC_POSTGRES_URL",
        "PostgreSQL credential",
      ),
      /regular non-symlink/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("host secret source rejects empty, oversized, and NUL-bearing secret files", async () => {
  const directory = await mkdtemp(join(tmpdir(), "synsec-secret-"));
  try {
    const empty = join(directory, "empty");
    const oversized = join(directory, "oversized");
    const nul = join(directory, "nul");
    await writeFile(empty, "");
    await writeFile(oversized, "x".repeat(8193));
    await writeFile(nul, "postgresql://db/synsec\0suffix");

    for (const path of [empty, oversized, nul]) {
      await assert.rejects(
        secretValueFromEnvironmentOrFile(
          { SYNSEC_POSTGRES_URL_FILE: path },
          "SYNSEC_POSTGRES_URL",
          "PostgreSQL credential",
        ),
      );
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
