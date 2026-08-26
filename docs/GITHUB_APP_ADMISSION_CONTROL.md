# GitHub App webhook admission control

SynSec's hosted GitHub App listener bounds the amount of webhook application work that one process can execute concurrently. This is transport-level resource protection for the repository-security service; it does not replace signature verification, replay protection, installation authorization, durable queue fencing, process/container limits, or upstream rate limiting.

## Runtime contract

`createGitHubAppServer()` accepts `maxConcurrentWebhooks`. The default is 100 concurrent webhook handlers and the configured value must be an integer from 1 through 1,000.

```ts
const server = createGitHubAppServer({
  host: "127.0.0.1",
  port: 3210,
  tlsMode: "terminated-upstream",
  maxConcurrentWebhooks: 50,
  webhookHandler: runtime.webhookHandler,
  getStatus: runtime.getStatus,
});
```

Only non-health requests consume a webhook handler slot. The aggregate-only health endpoint stays available while all webhook slots are occupied so a supervisor can still observe local runtime status.

When the process has reached its configured webhook limit, the listener does not invoke the webhook handler. It returns HTTP `503` with `Retry-After: 1` and the fixed body `{ "status": "busy" }`. The response does not contain repository identity, delivery ids, request bodies, scanner output, credentials, queue records, or exception text. A refused request therefore cannot create a replay claim or queue record, and GitHub can retry delivery later.

The slot is released in a `finally` path after the handler resolves or rejects. Handler exceptions continue to use the existing sanitized error boundary.

## Deployment guidance

Choose a limit based on the memory/CPU budget of the listener process and the capacity of its durable queue path. A higher number is not a substitute for horizontal scaling. The current filesystem-backed App runtime remains a single-host design; multiple hosts still require transactional shared authorization/replay/queue state with atomic insertion, fenced claims and renewals, and compare-and-set terminal transitions.

An ingress or reverse proxy should also enforce its own connection, request-body, and rate limits. SynSec's in-process admission limit starts after Node has accepted an HTTP request, so externally enforced limits remain necessary against connection floods or clients that never complete request bodies.

## Security boundary

Admission control never expands repository scope and never grants capabilities. Requests admitted to the handler still pass through exact-body HMAC verification, durable replay protection, installation/repository authorization, commit-pinned dispatch, and execution-time authorization checks. Refused requests do not bypass those controls; they do not enter the handler at all.

This feature does not implement scanner sandboxing, host firewall policy, shared multi-host persistence, or autonomous target assessment.