#!/usr/bin/env node
import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import pg from "pg";
import { parseGitHubAppHostProfile } from "@synsec/github/app-host-profile";
import { createSynSecGitHubAppIntakeHost } from "@synsec/github/app-intake-host";

const MAX_JSON_BYTES = 1024 * 1024;
const MAX_TLS_BYTES = 1024 * 1024;
const MAX_DATABASE_URL_BYTES = 8192;

function usage() {
  return "Usage: node scripts/github-app-intake-host.mjs --profile <absolute-json-path> --conformance <absolute-json-path> [--tls-key <absolute-path> --tls-cert <absolute-path>]";
}

function parseArgs(argv) {
  const allowed = new Set(["--profile", "--conformance", "--tls-key", "--tls-cert"]);
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!allowed.has(flag) || typeof value !== "string" || !value || value.startsWith("--")) {
      throw new Error(usage());
    }
    if (Object.values(result).includes(undefined)) throw new Error(usage());
    const key = flag.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    if (result[key] !== undefined) throw new Error(usage());
    result[key] = value;
  }
  if (!result.profile || !result.conformance) throw new Error(usage());
  if (Boolean(result.tlsKey) !== Boolean(result.tlsCert)) {
    throw new Error("Local TLS requires both --tls-key and --tls-cert.");
  }
  return result;
}

async function readBoundedRegular(pathValue, maximumBytes, label) {
  if (typeof pathValue !== "string" || !isAbsolute(pathValue) || pathValue.includes("\0")) {
    throw new Error(`${label} path must be absolute.`);
  }
  const path = resolve(pathValue);
  const info = await lstat(path).catch(() => undefined);
  if (!info?.isFile() || info.isSymbolicLink() || info.size < 1 || info.size > maximumBytes) {
    throw new Error(`${label} must be a bounded regular non-symlink file.`);
  }
  return readFile(path, "utf8").catch(() => {
    throw new Error(`${label} could not be read.`);
  });
}

async function readJson(path, label) {
  const text = await readBoundedRegular(path, MAX_JSON_BYTES, label);
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

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [profileInput, conformanceReport] = await Promise.all([
    readJson(args.profile, "GitHub App host profile"),
    readJson(args.conformance, "GitHub App shared-state conformance report"),
  ]);
  const profile = parseGitHubAppHostProfile(profileInput);
  const tls = args.tlsKey
    ? {
        key: await readBoundedRegular(args.tlsKey, MAX_TLS_BYTES, "GitHub App TLS key"),
        cert: await readBoundedRegular(args.tlsCert, MAX_TLS_BYTES, "GitHub App TLS certificate"),
      }
    : undefined;
  if (profile.tlsMode === "local" && !tls) {
    throw new Error("Host profile requires local TLS but no TLS key/certificate files were supplied.");
  }
  if (profile.tlsMode !== "local" && tls) {
    throw new Error("TLS key/certificate files are accepted only when the host profile uses local TLS.");
  }

  const pool = new pg.Pool({
    connectionString: databaseUrlFromEnvironment(profile),
    max: Math.max(4, Math.min(32, profile.replicaCount * 4)),
    application_name: `synsec-intake:${profile.replicaId}`,
  });

  let host;
  let stopping;
  const stop = async () => {
    if (stopping) return stopping;
    stopping = (async () => {
      try {
        if (host) await host.close();
      } finally {
        await pool.end();
      }
    })();
    return stopping;
  };

  try {
    host = await createSynSecGitHubAppIntakeHost({
      profile: profileInput,
      pool,
      conformanceReport,
      ...(tls ? { tls } : {}),
      onWebhookError(error) {
        process.stderr.write(`${error.message}\n`);
      },
    });
    const address = await host.start();
    process.stdout.write(`${JSON.stringify({
      status: "started",
      releaseId: profile.releaseId,
      replicaId: profile.replicaId,
      protocol: address.protocol,
      host: address.host,
      port: address.port,
      interpretation: host.interpretation,
    })}\n`);

    for (const signal of ["SIGTERM", "SIGINT"]) {
      process.once(signal, () => {
        void stop().then(() => process.exit(0), () => process.exit(1));
      });
    }
  } catch (error) {
    await stop().catch(() => undefined);
    throw error;
  }
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : "GitHub App intake host failed.";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
