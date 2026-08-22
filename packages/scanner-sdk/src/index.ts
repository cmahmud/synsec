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
}

export interface ScannerAvailability {
  available: boolean;
  version?: string;
  reason?: string;
}

export interface ScannerAdapter {
  readonly id: string;
  readonly displayName: string;
  readonly capabilities: ScannerCapability[];
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
  env?: NodeJS.ProcessEnv;
}

export async function runProcess(
  command: string,
  args: string[],
  options: ProcessOptions = {},
): Promise<ProcessOutput> {
  return await new Promise<ProcessOutput>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let settled = false;

    const finish = (callback: () => void): void => {
      if (settled) return;
      settled = true;
      callback();
    };

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });

    const timeout = options.timeoutMs
      ? setTimeout(() => child.kill("SIGTERM"), options.timeoutMs)
      : undefined;

    const onAbort = (): void => child.kill("SIGTERM");
    options.signal?.addEventListener("abort", onAbort, { once: true });

    child.once("error", (error) => {
      finish(() => reject(error));
    });

    child.once("close", (code) => {
      if (timeout) clearTimeout(timeout);
      options.signal?.removeEventListener("abort", onAbort);
      finish(() =>
        resolve({
          exitCode: code ?? -1,
          stdout,
          stderr,
        }),
      );
    });
  });
}
