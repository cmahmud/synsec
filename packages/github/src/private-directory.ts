import { chmod, lstat, mkdir } from "node:fs/promises";

/**
 * Ensure one durable local state directory exists with restrictive permissions where supported.
 *
 * `mkdir({ mode })` only controls newly-created directories; an operator-created or restored
 * directory may already be more permissive. Repair that mode after creation so GitHub App durable
 * metadata does not remain directory-listable merely because the path pre-existed SynSec. The
 * final path itself must be a real directory rather than a symlink so permission repair does not
 * intentionally follow an alternate filesystem object.
 */
export async function ensurePrivateDirectory(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const metadata = await lstat(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("GitHub App durable state path must be a real directory, not a symlink or other filesystem object.");
  }
  if (process.platform !== "win32") await chmod(path, 0o700);
}
