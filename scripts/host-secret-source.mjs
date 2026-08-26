import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";

const MAX_SECRET_BYTES = 8192;

function normalizeSecretText(value) {
  return value.endsWith("\r\n") ? value.slice(0, -2) : value.endsWith("\n") ? value.slice(0, -1) : value;
}

async function readBoundedSecretFile(pathValue, label) {
  if (typeof pathValue !== "string" || !isAbsolute(pathValue) || pathValue.includes("\0")) {
    throw new Error(`${label} file path must be absolute.`);
  }
  const path = resolve(pathValue);
  const info = await lstat(path).catch(() => undefined);
  if (!info?.isFile() || info.isSymbolicLink() || info.size < 1 || info.size > MAX_SECRET_BYTES) {
    throw new Error(`${label} file must be a bounded regular non-symlink file.`);
  }
  const text = await readFile(path, "utf8").catch(() => {
    throw new Error(`${label} file could not be read.`);
  });
  const normalized = normalizeSecretText(text);
  if (!normalized || Buffer.byteLength(normalized, "utf8") > MAX_SECRET_BYTES || normalized.includes("\0")) {
    throw new Error(`${label} file content is invalid.`);
  }
  return normalized;
}

export async function secretValueFromEnvironmentOrFile(environment, name, label) {
  const direct = environment[name];
  const fileName = `${name}_FILE`;
  const file = environment[fileName];
  const hasDirect = typeof direct === "string" && direct.length > 0;
  const hasFile = typeof file === "string" && file.length > 0;

  if (hasDirect && hasFile) {
    throw new Error(`${label} must be supplied by exactly one of ${name} or ${fileName}.`);
  }
  if (!hasDirect && !hasFile) {
    throw new Error(`${label} is missing.`);
  }

  const value = hasFile ? await readBoundedSecretFile(file, label) : direct;
  if (typeof value !== "string" || !value || Buffer.byteLength(value, "utf8") > MAX_SECRET_BYTES || value.includes("\0")) {
    throw new Error(`${label} is invalid.`);
  }
  return value;
}
