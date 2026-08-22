import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

export interface FindingReviewComment {
  id: string;
  fingerprint: string;
  body: string;
  createdAt: string;
  author?: string;
}

export interface FindingReviewCommentStore {
  schemaVersion: 1;
  comments: Record<string, FindingReviewComment[]>;
}

const MAX_STORE_BYTES = 8 * 1024 * 1024;
const MAX_TOTAL_COMMENTS = 100_000;
const MAX_COMMENTS_PER_FINDING = 100;
const MAX_FINGERPRINT_LENGTH = 512;
const MAX_COMMENT_ID_LENGTH = 128;
const MAX_AUTHOR_LENGTH = 255;
const MAX_BODY_LENGTH = 10_000;

function boundedText(value: unknown, maxLength: number, required = false): value is string {
  if (typeof value !== "string" || value.length > maxLength || /\0/.test(value)) return false;
  if (required && !value.trim()) return false;
  return true;
}

function validTimestamp(value: unknown): value is string {
  return boundedText(value, 128, true) && Number.isFinite(Date.parse(value));
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  const expected = [...allowed].sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

function isComment(value: unknown, fingerprint: string): value is FindingReviewComment {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const allowed = record.author === undefined
    ? ["id", "fingerprint", "body", "createdAt"]
    : ["id", "fingerprint", "body", "createdAt", "author"];
  if (!exactKeys(record, allowed)) return false;
  return boundedText(record.id, MAX_COMMENT_ID_LENGTH, true)
    && boundedText(record.fingerprint, MAX_FINGERPRINT_LENGTH, true)
    && record.fingerprint === fingerprint
    && boundedText(record.body, MAX_BODY_LENGTH, true)
    && validTimestamp(record.createdAt)
    && (record.author === undefined || boundedText(record.author, MAX_AUTHOR_LENGTH, true));
}

export function emptyFindingReviewCommentStore(): FindingReviewCommentStore {
  return { schemaVersion: 1, comments: {} };
}

export function isFindingReviewCommentStore(value: unknown): value is FindingReviewCommentStore {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const root = value as Record<string, unknown>;
  if (!exactKeys(root, ["schemaVersion", "comments"]) || root.schemaVersion !== 1) return false;
  if (typeof root.comments !== "object" || root.comments === null || Array.isArray(root.comments)) return false;

  let total = 0;
  for (const [fingerprint, comments] of Object.entries(root.comments as Record<string, unknown>)) {
    if (!boundedText(fingerprint, MAX_FINGERPRINT_LENGTH, true) || !Array.isArray(comments)) return false;
    if (comments.length === 0 || comments.length > MAX_COMMENTS_PER_FINDING) return false;
    total += comments.length;
    if (total > MAX_TOTAL_COMMENTS) return false;
    if (!comments.every((comment) => isComment(comment, fingerprint))) return false;
    const ids = new Set(comments.map((comment) => (comment as FindingReviewComment).id));
    if (ids.size !== comments.length) return false;
  }
  return true;
}

export async function readFindingReviewCommentStore(path: string): Promise<FindingReviewCommentStore> {
  try {
    const metadata = await stat(path);
    if (!metadata.isFile()) throw new Error(`SynSec finding review comment store is not a file: ${path}`);
    if (metadata.size > MAX_STORE_BYTES) {
      throw new Error(`SynSec finding review comment store exceeds the ${MAX_STORE_BYTES}-byte limit: ${path}`);
    }
    const parsed = JSON.parse(await readFile(path, "utf8")) as unknown;
    if (!isFindingReviewCommentStore(parsed)) {
      throw new Error(`Not a supported SynSec finding review comment store: ${path}`);
    }
    return parsed;
  } catch (error) {
    const code = typeof error === "object" && error !== null && "code" in error
      ? String((error as { code?: unknown }).code)
      : "";
    if (code === "ENOENT") return emptyFindingReviewCommentStore();
    throw error;
  }
}

export async function writeFindingReviewCommentStore(
  path: string,
  store: FindingReviewCommentStore,
): Promise<void> {
  if (!isFindingReviewCommentStore(store)) {
    throw new Error("Refusing to write an invalid SynSec finding review comment store.");
  }
  const serialized = `${JSON.stringify(store, null, 2)}\n`;
  if (Buffer.byteLength(serialized) > MAX_STORE_BYTES) {
    throw new Error(`SynSec finding review comment store exceeds the ${MAX_STORE_BYTES}-byte limit.`);
  }

  const directory = dirname(path);
  await mkdir(directory, { recursive: true });
  const temporaryPath = `${path}.${process.pid}.${Date.now()}.tmp`;
  try {
    await writeFile(temporaryPath, serialized, { encoding: "utf8", mode: 0o600, flag: "wx" });
    await chmod(temporaryPath, 0o600).catch(() => undefined);
    await rename(temporaryPath, path);
    await chmod(path, 0o600).catch(() => undefined);
  } finally {
    await rm(temporaryPath, { force: true }).catch(() => undefined);
  }
}

function commentId(fingerprint: string, body: string, author: string | undefined, createdAt: string): string {
  return createHash("sha256")
    .update(fingerprint)
    .update("\0")
    .update(createdAt)
    .update("\0")
    .update(author ?? "")
    .update("\0")
    .update(body)
    .digest("hex");
}

/**
 * Append bounded human triage commentary without modifying finding state or scanner evidence.
 *
 * Comment text is operator-supplied metadata only. SynSec does not automatically copy source
 * excerpts, scanner diagnostics, tokens, or repository credentials into this store. The API is
 * append-only so prior review context cannot be silently rewritten by a later scan.
 */
export function addFindingReviewComment(
  store: FindingReviewCommentStore,
  fingerprint: string,
  body: string,
  options: { author?: string; createdAt?: string } = {},
): FindingReviewCommentStore {
  const normalizedFingerprint = fingerprint.trim();
  const normalizedBody = body.trim();
  const author = options.author?.trim() || undefined;
  const createdAt = options.createdAt ?? new Date().toISOString();

  if (!boundedText(normalizedFingerprint, MAX_FINGERPRINT_LENGTH, true)) {
    throw new Error(`Finding fingerprint must be at most ${MAX_FINGERPRINT_LENGTH} characters.`);
  }
  if (!boundedText(normalizedBody, MAX_BODY_LENGTH, true)) {
    throw new Error(`Finding review comment must be between 1 and ${MAX_BODY_LENGTH} characters and contain no NUL bytes.`);
  }
  if (author !== undefined && !boundedText(author, MAX_AUTHOR_LENGTH, true)) {
    throw new Error(`Finding review comment author must be at most ${MAX_AUTHOR_LENGTH} characters.`);
  }
  if (!validTimestamp(createdAt)) throw new Error("Finding review comment timestamp must be valid.");

  const existing = store.comments[normalizedFingerprint] ?? [];
  if (existing.length >= MAX_COMMENTS_PER_FINDING) {
    throw new Error(`Finding review comments are limited to ${MAX_COMMENTS_PER_FINDING} entries per finding.`);
  }
  const total = Object.values(store.comments).reduce((count, comments) => count + comments.length, 0);
  if (total >= MAX_TOTAL_COMMENTS) {
    throw new Error(`Finding review comment store is limited to ${MAX_TOTAL_COMMENTS} total comments.`);
  }

  const comment: FindingReviewComment = {
    id: commentId(normalizedFingerprint, normalizedBody, author, createdAt),
    fingerprint: normalizedFingerprint,
    body: normalizedBody,
    createdAt,
    ...(author ? { author } : {}),
  };
  if (existing.some((item) => item.id === comment.id)) return store;

  return {
    schemaVersion: 1,
    comments: {
      ...store.comments,
      [normalizedFingerprint]: [...existing, comment],
    },
  };
}

export function commentsForFinding(
  store: FindingReviewCommentStore,
  fingerprint: string,
): readonly FindingReviewComment[] {
  return [...(store.comments[fingerprint.trim()] ?? [])]
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id));
}
