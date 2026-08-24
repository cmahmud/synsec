import { lstat } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { runProcess, type ProcessOutput } from "./index.js";

const DEFAULT_CPU_LIMIT = 2;
const MIN_CPU_LIMIT = 0.1;
const MAX_CPU_LIMIT = 64;
const DEFAULT_MEMORY_BYTES = 2 * 1024 * 1024 * 1024;
const MIN_MEMORY_BYTES = 64 * 1024 * 1024;
const MAX_MEMORY_BYTES = 64 * 1024 * 1024 * 1024;
const DEFAULT_PIDS_LIMIT = 256;
const MIN_PIDS_LIMIT = 16;
const MAX_PIDS_LIMIT = 4096;
const DEFAULT_SCRATCH_BYTES = 512 * 1024 * 1024;
const MIN_SCRATCH_BYTES = 16 * 1024 * 1024;
const MAX_SCRATCH_BYTES = 16 * 1024 * 1024 * 1024;
const DEFAULT_CONTAINER_USER = "65532:65532";
const DEFAULT_CONTAINER_WORKDIR = "/workspace";

export interface OciScannerSandboxOptions {
  /** Bare or absolute local OCI CLI. Defaults to docker. */
  runtimeCommand?: string;
  /** Pre-provisioned immutable scanner image. Mutable tags are rejected. */
  image: string;
  /** Absolute host repository directory mounted read-only at /workspace. */
  repositoryRoot: string;
  cpuLimit?: number;
  memoryBytes?: number;
  pidsLimit?: number;
  scratchBytes?: number;
  /** Numeric non-root uid:gid. Defaults to 65532:65532. */
  runAsUser?: string;
  timeoutMs?: number;
  signal?: AbortSignal;
  maxOutputBytes?: number;
  killGraceMs?: number;
}

interface NumericContainerUser {
  uid: number;
  gid: number;
  value: string;
}

function boundedInteger(value: number | undefined, fallback: number, minimum: number, maximum: number, label: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < minimum || resolved > maximum) {
    throw new Error(`${label} must be an integer between ${minimum} and ${maximum}.`);
  }
  return resolved;
}

function boundedCpu(value: number | undefined): number {
  const resolved = value ?? DEFAULT_CPU_LIMIT;
  if (!Number.isFinite(resolved) || resolved < MIN_CPU_LIMIT || resolved > MAX_CPU_LIMIT) {
    throw new Error(`OCI scanner CPU limit must be between ${MIN_CPU_LIMIT} and ${MAX_CPU_LIMIT}.`);
  }
  return resolved;
}

function immutableImage(value: string): string {
  if (typeof value !== "string" || !value || value.length > 512 || /[\s\u0000-\u001f\u007f]/.test(value)) {
    throw new Error("OCI scanner image must be a bounded non-secret image reference.");
  }
  if (!/@sha256:[a-f0-9]{64}$/i.test(value)) {
    throw new Error("OCI scanner image must be pinned by sha256 digest; mutable tags are not allowed.");
  }
  return value;
}

function numericNonRootUser(value: string | undefined): NumericContainerUser {
  const normalized = value ?? DEFAULT_CONTAINER_USER;
  const match = /^(\d+):(\d+)$/.exec(normalized);
  if (!match) throw new Error("OCI scanner user must be a numeric uid:gid pair.");
  const uid = Number(match[1]);
  const gid = Number(match[2]);
  if (!Number.isSafeInteger(uid) || !Number.isSafeInteger(gid) || uid <= 0 || gid <= 0 || uid > 2_147_483_647 || gid > 2_147_483_647) {
    throw new Error("OCI scanner user must use positive bounded non-root uid/gid values.");
  }
  return { uid, gid, value: `${uid}:${gid}` };
}

function repositoryRoot(value: string): string {
  if (typeof value !== "string" || !isAbsolute(value) || value.includes("\0") || value.includes(",")) {
    throw new Error("OCI scanner repository root must be an absolute mount-safe path.");
  }
  return resolve(value);
}

function scannerToken(value: string, label: string): string {
  if (typeof value !== "string" || !value || value.length > 32_768 || /[\u0000\r\n]/.test(value)) {
    throw new Error(`${label} must be a bounded single-line string.`);
  }
  return value;
}

function ownedTmpfs(path: "/scratch" | "/tmp", bytes: number, user: NumericContainerUser): string {
  return `${path}:rw,noexec,nosuid,nodev,size=${bytes},uid=${user.uid},gid=${user.gid},mode=0700`;
}

export interface OciScannerSandboxPlan {
  runtimeCommand: string;
  runtimeArgs: string[];
  repositoryRoot: string;
  image: string;
  /** Concrete controls created by this invocation, not an operator declaration. */
  enforcedControls: {
    networkPolicy: "none";
    repositoryReadOnly: true;
    rootFilesystemReadOnly: true;
    scratchSeparated: true;
    runAsNonRoot: true;
    capabilitiesDropped: true;
    allowPrivilegeEscalation: false;
    hostNetwork: false;
    hostPid: false;
    hostIpc: false;
    hostSocketMounts: false;
    pullPolicy: "never";
  };
}

/**
 * Produce the exact OCI CLI invocation used by runOciSandboxedScanner().
 *
 * The plan deliberately supports only network=none. Domain/CIDR-filtered egress requires an
 * external network-policy implementation and must not be simulated with unrestricted bridge mode.
 */
export function buildOciScannerSandboxPlan(
  commandValue: string,
  argsValue: readonly string[],
  options: OciScannerSandboxOptions,
): OciScannerSandboxPlan {
  const runtimeCommand = scannerToken(options.runtimeCommand ?? "docker", "OCI runtime command");
  const image = immutableImage(options.image);
  const root = repositoryRoot(options.repositoryRoot);
  const command = scannerToken(commandValue, "OCI scanner command");
  const args = argsValue.map((value) => scannerToken(value, "OCI scanner argument"));
  const cpuLimit = boundedCpu(options.cpuLimit);
  const memoryBytes = boundedInteger(
    options.memoryBytes,
    DEFAULT_MEMORY_BYTES,
    MIN_MEMORY_BYTES,
    MAX_MEMORY_BYTES,
    "OCI scanner memory limit",
  );
  const pidsLimit = boundedInteger(
    options.pidsLimit,
    DEFAULT_PIDS_LIMIT,
    MIN_PIDS_LIMIT,
    MAX_PIDS_LIMIT,
    "OCI scanner PID limit",
  );
  const scratchBytes = boundedInteger(
    options.scratchBytes,
    DEFAULT_SCRATCH_BYTES,
    MIN_SCRATCH_BYTES,
    MAX_SCRATCH_BYTES,
    "OCI scanner scratch limit",
  );
  const user = numericNonRootUser(options.runAsUser);

  const runtimeArgs = [
    "run",
    "--rm",
    "--init",
    "--pull=never",
    "--network=none",
    "--ipc=none",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges=true",
    `--pids-limit=${pidsLimit}`,
    `--memory=${memoryBytes}`,
    `--memory-swap=${memoryBytes}`,
    `--cpus=${cpuLimit}`,
    `--user=${user.value}`,
    "--mount",
    `type=bind,src=${root},dst=${DEFAULT_CONTAINER_WORKDIR},readonly`,
    "--tmpfs",
    ownedTmpfs("/scratch", scratchBytes, user),
    "--tmpfs",
    ownedTmpfs("/tmp", scratchBytes, user),
    `--workdir=${DEFAULT_CONTAINER_WORKDIR}`,
    "--env=HOME=/scratch",
    "--env=TMPDIR=/tmp",
    "--env=XDG_CACHE_HOME=/scratch/cache",
    image,
    command,
    ...args,
  ];

  return {
    runtimeCommand,
    runtimeArgs,
    repositoryRoot: root,
    image,
    enforcedControls: {
      networkPolicy: "none",
      repositoryReadOnly: true,
      rootFilesystemReadOnly: true,
      scratchSeparated: true,
      runAsNonRoot: true,
      capabilitiesDropped: true,
      allowPrivilegeEscalation: false,
      hostNetwork: false,
      hostPid: false,
      hostIpc: false,
      hostSocketMounts: false,
      pullPolicy: "never",
    },
  };
}

/**
 * Execute one scanner command inside a locally provisioned OCI image with enforced isolation.
 *
 * The repository path is independently checked with lstat immediately before the container starts;
 * symlink roots and non-directories are rejected. The OCI CLI itself runs through SynSec's existing
 * bounded process runner, so it receives the same credential-minimized host environment, timeout,
 * abort, output-memory, and kill-escalation controls as other external processes.
 */
export async function runOciSandboxedScanner(
  command: string,
  args: readonly string[],
  options: OciScannerSandboxOptions,
): Promise<ProcessOutput> {
  const plan = buildOciScannerSandboxPlan(command, args, options);
  const info = await lstat(plan.repositoryRoot).catch(() => undefined);
  if (!info?.isDirectory() || info.isSymbolicLink()) {
    throw new Error("OCI scanner repository root must be an existing non-symlink directory.");
  }
  return runProcess(plan.runtimeCommand, plan.runtimeArgs, {
    timeoutMs: options.timeoutMs,
    signal: options.signal,
    maxOutputBytes: options.maxOutputBytes,
    killGraceMs: options.killGraceMs,
  });
}
