import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import type { AddressInfo } from "node:net";
import type { GitHubAppRuntimeStatus } from "./app-status.js";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_HEADERS_TIMEOUT_MS = 10_000;
const DEFAULT_KEEP_ALIVE_TIMEOUT_MS = 5_000;
const DEFAULT_SHUTDOWN_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_CONCURRENT_WEBHOOKS = 100;
const MIN_TIMEOUT_MS = 1_000;
const MAX_TIMEOUT_MS = 120_000;
const MAX_REQUESTS_PER_SOCKET = 100;
const MAX_CONCURRENT_WEBHOOKS = 1_000;

export type GitHubAppServerTlsMode = "local" | "terminated-upstream" | "none";

export interface GitHubAppServerTlsOptions {
  key: string | Buffer;
  cert: string | Buffer;
}

export interface GitHubAppServerOptions {
  host: string;
  port: number;
  tlsMode: GitHubAppServerTlsMode;
  webhookHandler(request: import("node:http").IncomingMessage, response: import("node:http").ServerResponse): Promise<void>;
  tls?: GitHubAppServerTlsOptions;
  healthPath?: string;
  /** Minimal routing-readiness probe path. Defaults to /readyz and must differ from healthPath. */
  readinessPath?: string;
  getStatus?: () => Promise<GitHubAppRuntimeStatus>;
  /**
   * Optional fail-closed readiness policy evaluated only after aggregate runtime status loads.
   * The predicate result is never serialized into the response; callers receive only ready/not_ready.
   */
  isReady?: (status: GitHubAppRuntimeStatus) => boolean | Promise<boolean>;
  requestTimeoutMs?: number;
  headersTimeoutMs?: number;
  keepAliveTimeoutMs?: number;
  shutdownTimeoutMs?: number;
  /** Maximum webhook handlers allowed to execute concurrently in this listener process. */
  maxConcurrentWebhooks?: number;
}

export interface GitHubAppServerAddress {
  host: string;
  port: number;
  protocol: "http" | "https";
}

export interface GitHubAppServer {
  readonly server: HttpServer | HttpsServer;
  start(): Promise<GitHubAppServerAddress>;
  close(): Promise<void>;
}

function boundedTimeout(value: number | undefined, fallback: number, label: string): number {
  const timeout = value ?? fallback;
  if (!Number.isSafeInteger(timeout) || timeout < MIN_TIMEOUT_MS || timeout > MAX_TIMEOUT_MS) {
    throw new Error(`${label} must be between ${MIN_TIMEOUT_MS} and ${MAX_TIMEOUT_MS} milliseconds.`);
  }
  return timeout;
}

function boundedConcurrentWebhooks(value: number | undefined): number {
  const limit = value ?? DEFAULT_MAX_CONCURRENT_WEBHOOKS;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_CONCURRENT_WEBHOOKS) {
    throw new Error(`GitHub App concurrent webhook limit must be between 1 and ${MAX_CONCURRENT_WEBHOOKS}.`);
  }
  return limit;
}

function normalizedHost(value: string): string {
  const host = value.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (!host || host === "*" || /[\s/]/.test(host)) {
    throw new Error("GitHub App listener host must be a host name or IP address, not a URL, wildcard, or path.");
  }
  return host;
}

function normalizedPort(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > 65_535) {
    throw new Error("GitHub App listener port must be an integer between 0 and 65535.");
  }
  return value;
}

function normalizedProbePath(value: string | undefined, fallback: string, label: string): string {
  const path = value?.trim() || fallback;
  if (!path.startsWith("/") || path.includes("?") || path.includes("#") || /[\r\n]/.test(path)) {
    throw new Error(`${label} must be an absolute path without query, fragment, or control components.`);
  }
  return path;
}

function sendJson(response: import("node:http").ServerResponse, statusCode: number, payload: Record<string, unknown>): void {
  const body = `${JSON.stringify(payload)}\n`;
  response.statusCode = statusCode;
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.setHeader("content-length", Buffer.byteLength(body));
  response.setHeader("cache-control", "no-store");
  response.setHeader("x-content-type-options", "nosniff");
  response.end(body);
}

function safeStatus(status: GitHubAppRuntimeStatus): Record<string, unknown> {
  return {
    status: "ok",
    installations: {
      total: status.installations.total,
      active: status.installations.active,
      suspended: status.installations.suspended,
      allRepositories: status.installations.allRepositories,
      selectedRepositories: status.installations.selectedRepositories,
    },
    queue: {
      total: status.queue.total,
      pending: status.queue.pending,
      leased: status.queue.leased,
      expiredLeases: status.queue.expiredLeases,
      failed: status.queue.failed,
    },
  };
}

/**
 * Create a bounded single-process listener for SynSec's hosted GitHub App runtime.
 *
 * Plain HTTP is restricted to loopback unless the operator explicitly declares upstream TLS
 * termination. Local TLS requires an in-memory key/certificate pair. Request/header/keep-alive
 * timeouts, per-socket request counts, and in-process concurrent webhook handlers are bounded.
 * Excess webhook concurrency fails fast with a retryable aggregate-only 503 response while the
 * health and readiness probes remain available. The health surface contains aggregate runtime
 * counts only. The readiness surface is intentionally smaller: it confirms durable status can be
 * loaded and, when configured, that a local readiness predicate accepts that status, but returns
 * only `ready` or `not_ready`. Repository identities, delivery ids, commit SHAs, source paths,
 * credentials, predicate diagnostics, and arbitrary durable-record fields are never serialized.
 */
export function createGitHubAppServer(options: GitHubAppServerOptions): GitHubAppServer {
  const host = normalizedHost(options.host);
  const port = normalizedPort(options.port);
  const healthPath = normalizedProbePath(options.healthPath, "/healthz", "GitHub App health path");
  const readinessPath = normalizedProbePath(options.readinessPath, "/readyz", "GitHub App readiness path");
  if (healthPath === readinessPath) {
    throw new Error("GitHub App health and readiness paths must be distinct.");
  }
  if (options.isReady && !options.getStatus) {
    throw new Error("GitHub App readiness policy requires aggregate runtime status collection.");
  }

  const requestTimeoutMs = boundedTimeout(options.requestTimeoutMs, DEFAULT_REQUEST_TIMEOUT_MS, "GitHub App request timeout");
  const headersTimeoutMs = boundedTimeout(options.headersTimeoutMs, DEFAULT_HEADERS_TIMEOUT_MS, "GitHub App headers timeout");
  const keepAliveTimeoutMs = boundedTimeout(options.keepAliveTimeoutMs, DEFAULT_KEEP_ALIVE_TIMEOUT_MS, "GitHub App keep-alive timeout");
  const shutdownTimeoutMs = boundedTimeout(options.shutdownTimeoutMs, DEFAULT_SHUTDOWN_TIMEOUT_MS, "GitHub App shutdown timeout");
  const maxConcurrentWebhooks = boundedConcurrentWebhooks(options.maxConcurrentWebhooks);

  if (options.tlsMode === "none" && !LOOPBACK_HOSTS.has(host)) {
    throw new Error("A plaintext GitHub App listener is allowed only on loopback.");
  }
  if (options.tlsMode === "local" && (!options.tls?.key || !options.tls.cert)) {
    throw new Error("Local GitHub App TLS requires both key and certificate material.");
  }
  if (options.tlsMode !== "local" && options.tls !== undefined) {
    throw new Error("GitHub App TLS key/certificate material is accepted only in local TLS mode.");
  }

  let activeWebhookRequests = 0;

  const requestListener = async (
    request: import("node:http").IncomingMessage,
    response: import("node:http").ServerResponse,
  ): Promise<void> => {
    const requestPath = (request.url ?? "").split("?", 1)[0];
    if (requestPath === healthPath) {
      if (request.method !== "GET") {
        response.setHeader("allow", "GET");
        sendJson(response, 405, { status: "method_not_allowed" });
        return;
      }
      try {
        const status = options.getStatus ? safeStatus(await options.getStatus()) : { status: "ok" };
        sendJson(response, 200, status);
      } catch {
        sendJson(response, 503, { status: "unavailable" });
      }
      return;
    }

    if (requestPath === readinessPath) {
      if (request.method !== "GET") {
        response.setHeader("allow", "GET");
        sendJson(response, 405, { status: "method_not_allowed" });
        return;
      }
      try {
        if (!options.getStatus) {
          sendJson(response, 200, { status: "ready" });
          return;
        }
        const status = await options.getStatus();
        const ready = options.isReady ? await options.isReady(status) : true;
        sendJson(response, ready ? 200 : 503, { status: ready ? "ready" : "not_ready" });
      } catch {
        sendJson(response, 503, { status: "not_ready" });
      }
      return;
    }

    if (activeWebhookRequests >= maxConcurrentWebhooks) {
      response.setHeader("retry-after", "1");
      sendJson(response, 503, { status: "busy" });
      return;
    }

    activeWebhookRequests += 1;
    try {
      await options.webhookHandler(request, response);
    } catch {
      if (!response.headersSent) sendJson(response, 500, { status: "error" });
      else if (!response.writableEnded) response.end();
    } finally {
      activeWebhookRequests -= 1;
    }
  };

  const server: HttpServer | HttpsServer = options.tlsMode === "local"
    ? createHttpsServer({ key: options.tls?.key, cert: options.tls?.cert }, requestListener)
    : createHttpServer(requestListener);

  server.requestTimeout = requestTimeoutMs;
  server.headersTimeout = Math.min(headersTimeoutMs, requestTimeoutMs);
  server.keepAliveTimeout = keepAliveTimeoutMs;
  server.maxRequestsPerSocket = MAX_REQUESTS_PER_SOCKET;

  let started = false;

  return {
    server,
    start: async () => {
      if (started) throw new Error("GitHub App server is already started.");
      await new Promise<void>((resolvePromise, reject) => {
        const onError = (error: Error): void => reject(error);
        server.once("error", onError);
        server.listen({ host, port, exclusive: true }, () => {
          server.off("error", onError);
          resolvePromise();
        });
      });
      started = true;
      const address = server.address();
      if (!address || typeof address === "string") {
        throw new Error("GitHub App server did not expose a TCP listener address.");
      }
      const info = address as AddressInfo;
      return {
        host: info.address,
        port: info.port,
        protocol: options.tlsMode === "local" ? "https" : "http",
      };
    },
    close: async () => {
      if (!started) return;
      await new Promise<void>((resolvePromise, reject) => {
        const forceTimer = setTimeout(() => server.closeAllConnections?.(), shutdownTimeoutMs);
        forceTimer.unref?.();
        server.close((error) => {
          clearTimeout(forceTimer);
          server.closeIdleConnections?.();
          if (error) reject(error);
          else resolvePromise();
        });
      });
      started = false;
    },
  };
}
