import { spawn } from "node:child_process";
import { delimiter, isAbsolute, relative, resolve } from "node:path";
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

/** Injectable execution boundary used by scanner adapters. */
export type ScannerProcessRunner = (
  command: string,
  args: string[],
  options?: ProcessOptions,
) => Promise<ProcessOutput>;

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
  "LANG",
  "LC_ALL",
  "TERM",
  "COLORTERM",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "NODE_EXTRA_CA_CERTS",
  "XDG_CACHE_HOME",
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
    .replace(/([?&](?:access[_-]?token|auth[_-]?token|api[_-]?key|password|passwd|token)=)[^&#\s]+/gi, "$1[REDACTED]")
    .replace(/\b(?:github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9_]+)\b/g, "[REDACTED_TOKEN]")
    .replace(/\bAKIA[A-Z0-9]{16}\b/g, "[REDACTED_ACCESS_KEY]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[REDACTED_JWT]")
    .replace(
      /(\b(?:authorization|proxy-authorization)\s*[:=]\s*)(?:bearer\s+)?(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)/gi,
      "$1[REDACTED]",
    )
    .replace(
      /(\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd)\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)/gi,
      "$1[REDACTED]",
    )
    .trim();
  if (text.length > maxLength) text = `${text.slice(0, maxLength)}…[truncated]`;
  return text;
}

function isWithinDirectory(candidate: string, root: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

/**
 * Remove relative/empty PATH entries and, when a scanner working directory is known, directories
 * inside that working tree. This prevents repository-controlled executables from shadowing the
 * intended scanner binary through `.` or repository-local `.bin` entries.
 */
export function sanitizeScannerSearchPath(value: string, cwd?: string): string | undefined {
  const root = cwd ? resolve(cwd) : undefined;
  const seen = new Set<string>();
  const entries: string[] = [];
  for (const raw of value.split(delimiter)) {
    const entry = raw.trim();
    if (!entry || !isAbsolute(entry)) continue;
    const absolute = resolve(entry);
    if (root && isWithinDirectory(absolute, root)) continue;
    const key = process.platform === "win32" ? absolute.toLowerCase() : absolute;
    if (seen.has(key)) continue;
    seen.add(key);
    entries.push(absolute);
  }
  return entries.length > 0 ? entries.join(delimiter) : undefined;
}

/**
 * Build the default environment for untrusted external scanner processes.
 * Credentials, CI tokens, cloud secrets, registry tokens, proxy URLs, and user configuration roots
 * are not inherited implicitly. In particular, HOME/USERPROFILE/AppData/XDG_CONFIG_HOME are omitted
 * because scanner-specific config files under those roots can contain credentials even when token
 * environment variables themselves have been removed. PATH is restricted to absolute directories
 * outside the scanner working tree when `cwd` is provided.
 */
export function buildScannerProcessEnv(source: NodeJS.ProcessEnv = process.env, cwd?: string): NodeJS.ProcessEnv {
  const result: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(source)) {
    if (value === undefined) continue;
    const normalized = key.toUpperCase();
    if (normalized === "PATH") {
      const safePath = sanitizeScannerSearchPath(value, cwd);
      if (safePath) result[key] = safePath;
      continue;
    }
    if (SAFE_ENV_KEYS.has(normalized) || normalized.startsWith("LC_")) result[key] = value;
  }
  return result;
}

function assertSafeScannerCommand(command: string): void {
  if (!command.trim()) throw new Error("Scanner command must be non-empty.");
  if (/[\\/]/.test(command) && !isAbsolute(command)) {
    throw new Error("Relative scanner executable paths are not allowed; use a bare command name or an absolute path.");
  }
}

export async function runProcess(
  command: string,
  args: string[],
  options: ProcessOptions = {},
): Promise<ProcessOutput> {
  assertSafeScannerCommand(command);
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
      env: options.env ?? buildScannerProcessEnv(process.env, options.cwd),
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
      finish(() => {
        const sanitized = new Error(sanitizeOperationalText(error.message));
        sanitized.name = error.name;
        reject(sanitized);
      });
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
