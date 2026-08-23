import type { IncomingMessage, ServerResponse } from "node:http";
import { sanitizeOperationalText } from "@synsec/scanner-sdk";
import type { GitHubWebhookSecret } from "./app.js";
import {
  handleGitHubAppWebhook,
  type GitHubAppInstallationStore,
  type GitHubAppWebhookHandleResult,
  type GitHubWebhookReplayManager,
} from "./app-handler.js";
import type { GitHubScanJobEnqueuer } from "./app-dispatch.js";

const MAX_WEBHOOK_BODY_BYTES = 10 * 1024 * 1024;
const DEFAULT_PATH = "/github/webhooks";

export interface GitHubAppWebhookHttpOptions {
  webhookSecret: GitHubWebhookSecret;
  replayStore: GitHubWebhookReplayManager;
  installationStore: GitHubAppInstallationStore;
  queue: GitHubScanJobEnqueuer;
  path?: string;
  onError?: (error: unknown) => void;
}

function header(request: IncomingMessage, name: string): string | undefined {
  const value = request.headers[name];
  if (Array.isArray(value)) return value[0]?.trim() || undefined;
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function sendJson(response: ServerResponse, statusCode: number, payload: Record<string, unknown>): void {
  const body = `${JSON.stringify(payload)}\n`;
  response.statusCode = statusCode;
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.setHeader("content-length", Buffer.byteLength(body));
  response.setHeader("cache-control", "no-store");
  response.end(body);
}

function resultStatus(result: GitHubAppWebhookHandleResult): number {
  return result.status === "queued" ? 202 : 200;
}

function publicResult(result: GitHubAppWebhookHandleResult): Record<string, unknown> {
  if (result.status === "queued") return { status: "queued" };
  if (result.status === "installation_updated") return { status: "installation_updated" };
  if (result.status === "installation_removed") return { status: "installation_removed" };
  if (result.status === "rejected") return { status: "ignored", reason: "installation_not_authorized" };
  return { status: "ignored", reason: result.reason };
}

function safeCallbackError(error: unknown): Error {
  const message = error instanceof Error ? error.message : String(error);
  return new Error(sanitizeOperationalText(message, 1000) || "GitHub App webhook processing failed.");
}

async function readBoundedBody(request: IncomingMessage): Promise<Buffer> {
  const declared = header(request, "content-length");
  if (declared !== undefined) {
    const length = Number(declared);
    if (!Number.isSafeInteger(length) || length < 0) throw new Error("invalid_content_length");
    if (length > MAX_WEBHOOK_BODY_BYTES) throw new Error("body_too_large");
  }

  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += buffer.byteLength;
    if (bytes > MAX_WEBHOOK_BODY_BYTES) throw new Error("body_too_large");
    chunks.push(buffer);
  }
  return Buffer.concat(chunks, bytes);
}

/**
 * Create a framework-free GitHub App webhook endpoint suitable for mounting behind HTTPS.
 *
 * The handler accepts only POST requests to one configured path, bounds the raw body before
 * signature processing, requires GitHub's event/delivery/signature headers, and delegates to the
 * replay-protected durable App handler. Internal error details are never returned to the caller.
 * Errors forwarded to the optional operator callback are also sanitized and bounded so hosted
 * logging integrations cannot accidentally persist credentials from backend/process failures.
 * A durable-processing failure returns 500 only after the App handler has attempted to release the
 * exact replay claim, allowing GitHub to retry the delivery instead of losing it.
 */
export function createGitHubAppWebhookHttpHandler(options: GitHubAppWebhookHttpOptions) {
  const path = options.path?.trim() || DEFAULT_PATH;
  if (!path.startsWith("/") || path.includes("?") || path.includes("#")) {
    throw new Error("GitHub App webhook path must be an absolute path without query or fragment components.");
  }
  const secretCount = typeof options.webhookSecret === "string" ? 1 : options.webhookSecret.length;
  if (secretCount < 1) throw new Error("GitHub App webhook secret is required.");

  return async function githubAppWebhookHttpHandler(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    const requestPath = (request.url ?? "").split("?", 1)[0];
    if (requestPath !== path) {
      sendJson(response, 404, { status: "not_found" });
      return;
    }
    if (request.method !== "POST") {
      response.setHeader("allow", "POST");
      sendJson(response, 405, { status: "method_not_allowed" });
      return;
    }
    const contentType = header(request, "content-type")?.toLowerCase();
    if (!contentType?.startsWith("application/json")) {
      sendJson(response, 415, { status: "unsupported_media_type" });
      return;
    }

    const signatureHeader = header(request, "x-hub-signature-256");
    const eventName = header(request, "x-github-event");
    const deliveryId = header(request, "x-github-delivery");
    if (!signatureHeader || !eventName || !deliveryId) {
      sendJson(response, 400, { status: "bad_request" });
      return;
    }

    let body: Buffer;
    try {
      body = await readBoundedBody(request);
    } catch (error) {
      if (error instanceof Error && error.message === "body_too_large") {
        sendJson(response, 413, { status: "payload_too_large" });
        return;
      }
      sendJson(response, 400, { status: "bad_request" });
      return;
    }

    try {
      const result = await handleGitHubAppWebhook({
        body,
        signatureHeader,
        webhookSecret: options.webhookSecret,
        eventName,
        deliveryId,
        replayStore: options.replayStore,
        installationStore: options.installationStore,
        queue: options.queue,
      });
      sendJson(response, resultStatus(result), publicResult(result));
    } catch (error) {
      options.onError?.(safeCallbackError(error));
      sendJson(response, 500, { status: "error" });
    }
  };
}
