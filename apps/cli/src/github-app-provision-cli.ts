#!/usr/bin/env node

import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  buildSynSecGitHubAppManifest,
  createSynSecGitHubAppManifestRegistration,
  type SynSecGitHubAppManifestOptions,
} from "@synsec/github/app-provisioning";

const MAX_CONFIG_BYTES = 64 * 1024;
const args = process.argv.slice(2);

function usage(): string {
  return "Usage: synsec-github-app-provision <provisioning.json> [--json]";
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function optionalString(root: Record<string, unknown>, key: string): string | undefined {
  const value = root[key];
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw new Error(`${key} must be a string.`);
  return value;
}

function optionalBoolean(root: Record<string, unknown>, key: string): boolean | undefined {
  const value = root[key];
  if (value === undefined) return undefined;
  if (typeof value !== "boolean") throw new Error(`${key} must be boolean.`);
  return value;
}

async function readConfig(path: string): Promise<{
  options: SynSecGitHubAppManifestOptions;
  organization?: string;
}> {
  const absolute = resolve(path);
  const info = await lstat(absolute).catch(() => undefined);
  if (!info || info.isSymbolicLink() || !info.isFile()) {
    throw new Error("GitHub App provisioning config must be a non-symlink regular file.");
  }
  if (info.size > MAX_CONFIG_BYTES) throw new Error(`GitHub App provisioning config exceeds ${MAX_CONFIG_BYTES} bytes.`);

  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(absolute, "utf8"));
  } catch {
    throw new Error("GitHub App provisioning config must contain valid JSON.");
  }
  const root = record(parsed);
  if (!root) throw new Error("GitHub App provisioning config must contain a JSON object.");

  const allowed = new Set([
    "homepageUrl",
    "webhookUrl",
    "redirectUrl",
    "setupUrl",
    "name",
    "description",
    "public",
    "setupOnUpdate",
    "publishSarif",
    "enableRemediationPullRequests",
    "organization",
  ]);
  for (const key of Object.keys(root)) {
    if (!allowed.has(key)) {
      throw new Error(`GitHub App provisioning config contains unsupported field ${key}. Credentials and secrets are not accepted.`);
    }
  }

  for (const key of ["homepageUrl", "webhookUrl", "redirectUrl"] as const) {
    if (typeof root[key] !== "string") throw new Error(`${key} is required and must be a string.`);
  }

  return {
    options: {
      homepageUrl: root.homepageUrl as string,
      webhookUrl: root.webhookUrl as string,
      redirectUrl: root.redirectUrl as string,
      ...(optionalString(root, "setupUrl") ? { setupUrl: optionalString(root, "setupUrl") } : {}),
      ...(optionalString(root, "name") ? { name: optionalString(root, "name") } : {}),
      ...(optionalString(root, "description") ? { description: optionalString(root, "description") } : {}),
      ...(optionalBoolean(root, "public") !== undefined ? { public: optionalBoolean(root, "public") } : {}),
      ...(optionalBoolean(root, "setupOnUpdate") !== undefined ? { setupOnUpdate: optionalBoolean(root, "setupOnUpdate") } : {}),
      ...(optionalBoolean(root, "publishSarif") !== undefined ? { publishSarif: optionalBoolean(root, "publishSarif") } : {}),
      ...(optionalBoolean(root, "enableRemediationPullRequests") !== undefined
        ? { enableRemediationPullRequests: optionalBoolean(root, "enableRemediationPullRequests") }
        : {}),
    },
    ...(optionalString(root, "organization") ? { organization: optionalString(root, "organization") } : {}),
  };
}

async function main(): Promise<void> {
  const path = args[0];
  if (!path || path.startsWith("--")) throw new Error(usage());
  const config = await readConfig(path);
  const manifest = buildSynSecGitHubAppManifest(config.options);
  const registration = createSynSecGitHubAppManifestRegistration({
    manifest,
    ...(config.organization ? { organization: config.organization } : {}),
  });

  if (args.includes("--json")) {
    console.log(JSON.stringify(registration, null, 2));
    return;
  }

  console.log(`Registration method: ${registration.method}`);
  console.log(`Registration endpoint: ${registration.action}`);
  console.log(`CSRF state: ${registration.fields.state}`);
  console.log("Manifest:");
  console.log(JSON.stringify(manifest, null, 2));
  console.log("Interpretation: registration request generated; GitHub App creation and manifest conversion are not yet complete.");
  console.log("Store the state in short-lived server-side session state and verify it on the manifest callback before conversion.");
}

main().catch((error: unknown) => {
  console.error(`SynSec GitHub App provisioning error: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
