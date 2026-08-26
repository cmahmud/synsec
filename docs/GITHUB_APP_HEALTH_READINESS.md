# GitHub App health and readiness probes

SynSec's hosted GitHub App listener exposes two separate operator-facing probe surfaces:

- `/healthz` is the aggregate operational health surface. When `getStatus` is configured it reports bounded installation and queue counts only. Repository identities, commit SHAs, delivery ids, source paths, credentials, scanner diagnostics, and arbitrary durable records are never serialized.
- `/readyz` is the routing-readiness surface. It returns only `{ "status": "ready" }` or `{ "status": "not_ready" }` and never includes the status object or readiness-policy diagnostics.

Both paths are configurable with `healthPath` and `readinessPath`, but they must be distinct absolute paths without query or fragment components. Only `GET` is accepted.

## Readiness semantics

If no `getStatus` callback is configured, `/readyz` reports ready once the listener is serving requests.

When `getStatus` is configured, readiness first requires aggregate durable state to load successfully. Operators may additionally supply an `isReady(status)` predicate for local policy. The predicate can inspect only the already-aggregated runtime status supplied by the host application. A false result, thrown error, or failed status read produces a minimal `503` response:

```json
{ "status": "not_ready" }
```

The listener deliberately does not prescribe a universal queue threshold. For example, retained failed jobs can be expected operational history rather than evidence that routing must stop, while an operator may reasonably decide that any expired worker lease should make one deployment temporarily unready. That policy belongs to the host deployment and can be expressed without exposing its reasoning over HTTP.

Example:

```ts
const server = createGitHubAppServer({
  host: "127.0.0.1",
  port: 3000,
  tlsMode: "none",
  webhookHandler,
  getStatus: () => buildGitHubAppRuntimeStatus({ installationStore, queue }),
  isReady: (status) => status.queue.expiredLeases === 0,
});
```

`isReady` requires `getStatus`; SynSec rejects a readiness policy that has no aggregate runtime status input.

## Admission control

Health and readiness probes bypass the in-process webhook concurrency admission limit. A saturated listener can therefore return `503 { "status": "busy" }` for additional webhook work while still exposing health and readiness to an orchestrator or supervisor.

This is intentional: probe traffic must not consume a webhook execution slot, and webhook saturation by itself is not silently converted into a durable-state failure.

## Deployment boundary

These probes do not implement external load balancing, TLS termination, restart policy, process supervision, ingress rate limiting, shared-state transactions, or scanner sandboxing. They provide a bounded signal that those external systems can consume.

For multi-replica deployments, the shared-state production-readiness contract and matching conformance evidence remain mandatory. A healthy HTTP listener does not certify that its backing state is safe for horizontal operation.
