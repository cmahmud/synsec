import { lstat, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";

export function nonEmpty(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed || undefined;
}

export function booleanInput(value: string | undefined, fallback: boolean): boolean {
  const normalized = value?.trim().toLowerCase();
  if (!normalized) return fallback;
  if (normalized === "true" || normalized === "1" || normalized === "yes") return true;
  if (normalized === "false" || normalized === "0" || normalized === "no") return false;
  throw new Error(`Expected a boolean action input, received: ${normalized.slice(0, 32)}`);
}

export function changedOnlyInput(value: string | undefined): boolean | undefined {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "auto") return undefined;
  if (normalized === "true" || normalized === "1" || normalized === "yes") return true;
  if (normalized === "false" || normalized === "0" || normalized === "no") return false;
  throw new Error("changed-only must be auto, true, or false.");
}

function insideRoot(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

/**
 * Resolve an explicitly configured Action file input and bind it to the checked-out workspace.
 * realpath() is used for both sides so a repository symlink cannot redirect config/baseline reads
 * into runner-global files outside the checkout.
 */
export async function resolveWorkspaceFileInput(
  workspace: string,
  input: string,
  label: string,
): Promise<string> {
  const root = await realpath(resolve(workspace));
  const lexicalCandidate = resolve(root, input);
  if (!insideRoot(root, lexicalCandidate)) {
    throw new Error(`${label} must resolve inside GITHUB_WORKSPACE.`);
  }

  const candidate = await realpath(lexicalCandidate).catch(() => undefined);
  if (!candidate || !insideRoot(root, candidate)) {
    throw new Error(`${label} must reference an existing file inside GITHUB_WORKSPACE.`);
  }
  const info = await lstat(candidate).catch(() => undefined);
  if (!info?.isFile()) {
    throw new Error(`${label} must reference a regular file inside GITHUB_WORKSPACE.`);
  }
  return candidate;
}
