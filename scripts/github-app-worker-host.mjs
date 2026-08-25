#!/usr/bin/env node
import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import pg from "pg";
import { parseConfig } from "@synsec/config";
import { parseGitHubAppHostProfile } from "@synsec/github/app-host-profile";
import { createSynSecGitHubAppWorkerHost } from "@synsec/github/app-worker-host";

const MAX_JSON_BYTES = 1024 * 1024;
const MAX_DATABASE_URL_BYTES = 8192;
const IDLE_DELAY_MS = 1_000;

function usage() {
  return "Usage: node scripts/github-app-worker-host.mjs --profile <absolute-json-path> --conformance <absolute-json-path> --config <absolute-json-path>";
}

function parseArgs(argv) {
  const allowed = new Set(["--profile", "--conformance", "--config"]);
  const result = {};
  if (argv.length % 2 !== 0) throw new Error(usage());
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!allowed.has(flag) || typeof value !== "string" || !value || value.startsWith("--")) {
      throw new Error(usage());
    }
    const key = flag.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    if (result[key] !== undefined) throw new Error(usage());
    result[key] = value;
  }
  if (!result.profile || !result.conformance || !result.config) throw new Error(usage());
  return result;
}

async function readJson(pathValue, label) {
  if (typeof pathValue !== "string" || !isAbsolute(pathValue) || pathValue.includes("\0")) {
    throw new Error(`${label} path must be absolute.`);
  }
  const path = resolve(pathValue);
  const info = await lstat(path).catch(() => undefined);
  if (!info?.isFile() || info.isSymbolicLink() || info.size < 1 || info.size > MAX_JSON_BYTES) {
    throw new Error(`${label} must be a bounded regular non-symlink file.`);
  }
  const text = await readFile(path, "utf8").catch(() => {
    throw new Error(`${label} could not be read.`);
  });
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${label} must contain valid JSON.`);
  }
}

function databaseUrlFromEnvironment(profile) {
  const value = process.env[profile.postgresUrlEnvironment];
  if (typeof value !== "string" || !value || Buffer.byteLength(value, "utf8") > MAX_DATABASE_URL_BYTES) {
    throw new Error("Configured PostgreSQL connection environment variable is missing or invalid.");
  }
  if (!/^postgres(?:ql)?:\/\//i.test(value)) {
    throw new Error("Configured PostgreSQL connection environment variable must contain a PostgreSQL URL.");
  }
  return value;
}

function delay(ms) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [profileInput, conformanceReport, configInput] = await Promise.all([
    readJson(args.profile, "GitHub App host profile"),
    readJson(args.conformance, "GitHub App shared-state conformance report"),
    readJson(args.config, "SynSec worker configuration"),
  ]);
  const profile = parseGitHubAppHostProfile(profileInput);
  const config = parseConfig(configInput);
  const pool = new pg.Pool({
    connectionString: databaseUrlFromEnvironment(profile),
    max: Math.max(4, Math.min(32, profile.replicaCount * 4)),
    application_name: `synsec-worker:${profile.replicaId}`,
  });

  let host;
  let stopping = false;
  let stopPromise;
  const stop = async () => {
    if (stopPromise) return stopPromise;
    stopping = true;
    stopPromise = (async () => {
      try {
        if (host) await host.close();
      } finally {
        await pool.end();
      }
    })();
    return stopPromise;
  };

  for (const signal of ["SIGTERM", "SIGINT"]) {
    process.once(signal, () => {
      void stop().then(() => process.exit(0), () => process.exit(1));
    });
  }

  try {
    host = await createSynSecGitHubAppWorkerHost({
      profile: profileInput,
      pool,
      conformanceReport,
      config,
      toolVersion: profile.releaseId,
    });
    process.stdout.write(`${JSON.stringify({
      status: "started",
      releaseId: profile.releaseId,
      replicaId: profile.replicaId,
      scanners: [...config.scanners].sort(),
      interpretation: host.interpretation,
    })}\n`);

    while (!stopping) {
      const result = await host.runOnce();
      if (result.status === "draining") break;
      if (result.status !== "idle") {
        // Do not emit repository, installation, finding, token, or backend diagnostics from the host loop.
        process.stdout.write(`${JSON.stringify({ status: result.status })}\n`);
      }
      if (result.status === "idle" || result.status === "retry_scheduled") await delay(IDLE_DELAY_MS);
    }
    await stop();
  } catch (error) {
    await stop().catch(() => undefined);
    throw error;
  }
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : "GitHub App worker host failed.";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
