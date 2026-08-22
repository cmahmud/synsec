import { chmod, mkdir } from "node:fs/promises";

/**
 * Ensure one durable local state directory exists with restrictive permissions where supported.
 *
 * `mkdir({ mode })` only controls newly-created directories; an operator-created or restored
 * directory may already be more permissive. Repair that mode after creation so GitHub App durable
 * metadata does not remain directory-listable merely because the path pre-existed SynSec.
 */
export async function ensurePrivateDirectory(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 });
  if (process.platform !== "win32") await chmod(path, 0o700);
}
