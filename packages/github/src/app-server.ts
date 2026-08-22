import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import type { AddressInfo } from "node:net";
import type { GitHubAppRuntimeStatus } from "./app-status.js";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_HEADERS_TIMEOUT_MS = 10_000;
const DEFAULT_KEEP_ALIVE_TIMEOUT_MS = 5_000;
const DEFAULT_SHUTDOWN_TIMEOUT_MS = 10_000;
const MIN_TIMEOUT_MS = 1_000;
const MAX_TIMEOUT_MS = 120_000;
const MAX_REQUESTS_PER_SOCKET = 100;

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
  getStatus?: () => Promise<GitHubAppRuntimeStatus>;
  requestTimeoutMs?: number;
  headersTimeoutMs?: number;
  keepAliveTimeoutMs?: number;
  shutdownTimeoutMs?: number;
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

function normalizedHealthPath(value: string | undefined): string {
  const path = value?.trim() || "/healthz";
  if (!path.startsWith("/") || path.includes("?") || path.includes("#")) {
    throw new Error("GitHub App health path must be an absolute path without query or fragment components.");
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
 * timeouts and per-socket request counts are bounded, and shutdown forcibly closes remaining
 * sockets after a bounded grace period. The built-in health surface contains aggregate runtime
 * counts only; repository identities, delivery ids, commit SHAs, source paths, and credentials are
 * never accepted as health payload fields.
 */
export function createGitHubAppServer(options: GitHubAppServerOptions): GitHubAppServer {
  const host = normalizedHost(options.host);
  const port = normalizedPort(options.port);
  const healthPath = normalizedHealthPath(options.healthPath);
  const requestTimeoutMs = boundedTimeout(options.requestTimeoutMs, DEFAULT_REQUEST_TIMEOUT_MS, "GitHub App request timeout");
  const headersTimeoutMs = boundedTimeout(options.headersTimeoutMs, DEFAULT_HEADERS_TIMEOUT_MS, "GitHub App headers timeout");
  const keepAliveTimeoutMs = boundedTimeout(options.keepAliveTimeoutMs, DEFAULT_KEEP_ALIVE_TIMEOUT_MS, "GitHub App keep-alive timeout");
  const shutdownTimeoutMs = boundedTimeout(options.shutdownTimeoutMs, DEFAULT_SHUTDOWN_TIMEOUT_MS, "GitHub App shutdown timeout");

  if (options.tlsMode === "none" && !LOOPBACK_HOSTS.has(host)) {
    throw new Error("A plaintext GitHub App listener is allowed only on loopback.");
  }
  if (options.tlsMode === "local" && (!options.tls?.key || !options.tls.cert)) {
    throw new Error("Local GitHub App TLS requires both key and certificate material.");
  }
  if (options.tlsMode !== "local" && options.tls !== undefined) {
    throw new Error("GitHub App TLS key/certificate material is accepted only in local TLS mode.");
  }

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

    try {
      await options.webhookHandler(request, response);
    } catch {
      if (!response.headersSent) sendJson(response, 500, { status: "error" });
      else if (!response.writableEnded) response.end();
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
