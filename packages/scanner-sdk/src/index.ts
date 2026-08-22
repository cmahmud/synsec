import { spawn } from "node:child_process";
import type { ScanResult, ScanTarget } from "@synsec/core";

export type ScannerCapability =
  | "sast"
  | "dependency"
  | "secret"
  | "iac"
  | "container"
  | "sbom"
  | "repository-posture";

export interface ScannerContext {
  target: ScanTarget;
  timeoutMs?: number;
  signal?: AbortSignal;
  /** Repository-relative files requested by an incremental scan. Adapters may use this to reduce work. */
  changedFiles?: string[];
}

export interface ScannerAvailability {
  available: boolean;
  version?: string;
  reason?: string;
}

export interface ScannerAdapter {
  readonly id: string;
  readonly displayName: string;
  readonly capabilities: readonly ScannerCapability[];
  checkAvailability(): Promise<ScannerAvailability>;
  scan(context: ScannerContext): Promise<ScanResult>;
}

export interface ProcessOutput {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface ProcessOptions {
  cwd?: string;
  timeoutMs?: number;
  signal?: AbortSignal;
  /** Explicit child environment. When omitted, SynSec passes only a small non-secret OS allowlist. */
  env?: NodeJS.ProcessEnv;
  /** Maximum bytes retained from each output stream. Defaults to 64 MiB per stream. */
  maxOutputBytes?: number;
  /** Grace period between SIGTERM and SIGKILL. Defaults to 2 seconds. */
  killGraceMs?: number;
}

const DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024 * 1024;
const DEFAULT_KILL_GRACE_MS = 2_000;
const DEFAULT_MAX_OPERATIONAL_TEXT = 8 * 1024;
const SAFE_ENV_KEYS = new Set([
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "COMSPEC",
  "WINDIR",
  "TEMP",
  "TMP",
  "TMPDIR",
  "HOME",
  "USERPROFILE",
  "LOCALAPPDATA",
  "APPDATA",
  "LANG",
  "LC_ALL",
  "TERM",
  "COLORTERM",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "NODE_EXTRA_CA_CERTS",
  "XDG_CACHE_HOME",
  "XDG_CONFIG_HOME",
]);

/**
 * Sanitize scanner/process diagnostics before they cross the operational reporting boundary.
 * This is deliberately conservative: diagnostics are for operators, not a source-evidence channel.
 */
export function sanitizeOperationalText(value: string, maxLength = DEFAULT_MAX_OPERATIONAL_TEXT): string {
  if (!Number.isFinite(maxLength) || maxLength <= 0) throw new Error("maxLength must be a positive finite number.");
  let text = value
    .replace(/\0/g, "")
    .replace(/[\u0001-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/@]+@/gi, "$1[REDACTED]@")
    .replace(/\b(?:github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9_]+)\b/g, "[REDACTED_TOKEN]")
    .replace(/\bAKIA[A-Z0-9]{16}\b/g, "[REDACTED_ACCESS_KEY]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[REDACTED_JWT]")
    .replace(/(\b(?:authorization|proxy-authorization)\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+/gi, "$1[REDACTED]")
    .replace(/(\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd)\s*[:=]\s*)[^\s,;]+/gi, "$1[REDACTED]")
    .trim();
  if (text.length > maxLength) text = `${text.slice(0, maxLength)}…[truncated]`;
  return text;
}

/**
 * Build the default environment for untrusted external scanner processes.
 * Credentials, CI tokens, cloud secrets, registry tokens, and proxy URLs are not inherited implicitly.
 */
export function buildScannerProcessEnv(source: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const result: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(source)) {
    if (value === undefined) continue;
    const normalized = key.toUpperCase();
    if (SAFE_ENV_KEYS.has(normalized) || normalized.startsWith("LC_")) result[key] = value;
  }
  return result;
}

export async function runProcess(
  command: string,
  args: string[],
  options: ProcessOptions = {},
): Promise<ProcessOutput> {
  if (options.signal?.aborted) throw new Error(`Process aborted before start: ${command}`);
  if (options.timeoutMs !== undefined && (!Number.isFinite(options.timeoutMs) || options.timeoutMs <= 0)) {
    throw new Error("timeoutMs must be a positive finite number when provided.");
  }
  const maxOutputBytes = options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  if (!Number.isFinite(maxOutputBytes) || maxOutputBytes <= 0) {
    throw new Error("maxOutputBytes must be a positive finite number.");
  }
  const killGraceMs = options.killGraceMs ?? DEFAULT_KILL_GRACE_MS;
  if (!Number.isFinite(killGraceMs) || killGraceMs < 0) {
    throw new Error("killGraceMs must be a non-negative finite number.");
  }

  return await new Promise<ProcessOutput>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env ?? buildScannerProcessEnv(),
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;
    let timedOut = false;
    let aborted = false;
    let overflowError: Error | undefined;
    let killEscalation: NodeJS.Timeout | undefined;

    const finish = (callback: () => void): void => {
      if (settled) return;
      settled = true;
      callback();
    };

    const terminate = (): void => {
      if (child.exitCode !== null || child.signalCode !== null) return;
      child.kill("SIGTERM");
      if (!killEscalation) {
        killEscalation = setTimeout(() => {
          if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
        }, killGraceMs);
      }
    };

    const stopForOverflow = (stream: "stdout" | "stderr", bytes: number): void => {
      if (overflowError) return;
      overflowError = new Error(
        `Process ${command} exceeded the ${maxOutputBytes} byte ${stream} limit (${bytes} bytes observed).`,
      );
      terminate();
    };

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdoutBytes += Buffer.byteLength(chunk);
      if (stdoutBytes > maxOutputBytes) {
        stopForOverflow("stdout", stdoutBytes);
        return;
      }
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderrBytes += Buffer.byteLength(chunk);
      if (stderrBytes > maxOutputBytes) {
        stopForOverflow("stderr", stderrBytes);
        return;
      }
      stderr += chunk;
    });

    const timeout = options.timeoutMs
      ? setTimeout(() => {
          timedOut = true;
          terminate();
        }, options.timeoutMs)
      : undefined;

    const onAbort = (): void => {
      aborted = true;
      terminate();
    };
    options.signal?.addEventListener("abort", onAbort, { once: true });

    const cleanup = (): void => {
      if (timeout) clearTimeout(timeout);
      if (killEscalation) clearTimeout(killEscalation);
      options.signal?.removeEventListener("abort", onAbort);
    };

    child.once("error", (error) => {
      cleanup();
      finish(() => reject(error));
    });

    child.once("close", (code) => {
      cleanup();
      finish(() => {
        if (overflowError) {
          reject(overflowError);
          return;
        }
        if (timedOut) {
          reject(new Error(`Process timed out after ${options.timeoutMs} ms: ${command}`));
          return;
        }
        if (aborted) {
          reject(new Error(`Process aborted: ${command}`));
          return;
        }
        resolve({
          exitCode: code ?? -1,
          stdout,
          stderr: sanitizeOperationalText(stderr),
        });
      });
    });
  });
}
