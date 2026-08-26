import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

const execFileAsync = promisify(execFile);
const cli = resolve("apps/cli/dist/github-app-provision-cli.js");

async function withConfig(value, operation) {
  const directory = await mkdtemp(join(tmpdir(), "synsec-app-provision-"));
  const path = join(directory, "provisioning.json");
  try {
    await writeFile(path, JSON.stringify(value), { encoding: "utf8", mode: 0o600 });
    return await operation(path);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function baseConfig(overrides = {}) {
  return {
    homepageUrl: "https://synsec.example/",
    webhookUrl: "https://synsec.example/github/webhooks",
    redirectUrl: "https://synsec.example/github/app/manifest/callback",
    setupUrl: "https://synsec.example/github/app/setup",
    organization: "SynSec-HQ",
    ...overrides,
  };
}

test("provisioning CLI emits a machine-readable organization manifest registration request", async () => {
  await withConfig(baseConfig({ publishSarif: true }), async (path) => {
    const { stdout, stderr } = await execFileAsync(process.execPath, [cli, path, "--json"], {
      encoding: "utf8",
    });
    assert.equal(stderr, "");
    const registration = JSON.parse(stdout);
    assert.equal(registration.method, "POST");
    assert.equal(
      registration.action,
      "https://github.com/organizations/SynSec-HQ/settings/apps/new",
    );
    assert.match(registration.fields.state, /^[A-Za-z0-9_-]{40,}$/);
    const manifest = JSON.parse(registration.fields.manifest);
    assert.equal(manifest.default_permissions.contents, "read");
    assert.equal(manifest.default_permissions.security_events, "write");
    assert.equal(manifest.setup_on_update, true);
  });
});

test("provisioning CLI rejects credential fields instead of accidentally serializing them", async () => {
  await withConfig(baseConfig({ privateKey: "do-not-accept" }), async (path) => {
    await assert.rejects(
      execFileAsync(process.execPath, [cli, path, "--json"], { encoding: "utf8" }),
      (error) => {
        assert.match(error.stderr, /unsupported field privateKey/);
        assert.match(error.stderr, /Credentials and secrets are not accepted/);
        assert.doesNotMatch(error.stdout ?? "", /do-not-accept/);
        return true;
      },
    );
  });
});

test("provisioning CLI rejects non-HTTPS production endpoints", async () => {
  await withConfig(baseConfig({ webhookUrl: "http://127.0.0.1:3000/webhook" }), async (path) => {
    await assert.rejects(
      execFileAsync(process.execPath, [cli, path, "--json"], { encoding: "utf8" }),
      (error) => {
        assert.match(error.stderr, /absolute HTTPS URL/);
        return true;
      },
    );
  });
});
