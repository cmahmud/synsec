# GitHub App runtime readiness policy

SynSec's hosted listener exposes a minimal `/readyz` probe and accepts an optional `isReady(status)` predicate. `@synsec/github/app-readiness-policy` provides a reusable fail-closed predicate for deployments that want routing readiness to account for aggregate queue health without exposing repository or installation identities.

## Default behavior

`assessGitHubAppRuntimeReadiness()` first validates that the aggregate status is internally consistent:

- installation counts are non-negative bounded integers;
- active plus suspended installations equals the installation total;
- all-repository plus selected-repository installations equals the installation total;
- pending plus leased plus failed jobs equals the queue total; and
- expired leases never exceed the leased-job count.

Malformed or contradictory status fails with the aggregate code `invalid-status`.

By default, any expired worker lease makes the runtime not ready. An expired lease is reclaimable work and can indicate a stalled or lost worker. Queue-depth and retained-failure limits are deployment-specific, so `maxPendingJobs` and `maxFailedJobs` are opt-in bounded thresholds.

## Listener integration

```ts
import { createGitHubAppServer } from "@synsec/github/app-server";
import {
  createGitHubAppRuntimeReadinessPredicate,
} from "@synsec/github/app-readiness-policy";

const server = createGitHubAppServer({
  host: "127.0.0.1",
  port: 3000,
  tlsMode: "terminated-upstream",
  webhookHandler,
  getStatus,
  isReady: createGitHubAppRuntimeReadinessPredicate({
    maxExpiredLeases: 0,
    maxPendingJobs: 500,
    maxFailedJobs: 50,
  }),
});
```

The listener continues to serialize only `{ "status": "ready" }` or `{ "status": "not_ready" }` from the readiness endpoint. Policy reason codes are local operator/developer diagnostics and are not exposed through the HTTP probe.

## Security boundary

Runtime readiness is a routing and operational-health signal, not a security certification. A ready result does not prove scanner sandboxing, network isolation, transactional shared state, GitHub authorization, credential correctness, or safe multi-replica deployment. Those controls remain separate production-readiness gates.

The policy consumes only aggregate counts. It does not accept repository names, installation ids, commit SHAs, credentials, scanner output, source paths, or arbitrary URLs, and it never broadens repository scope or initiates network assessment.
