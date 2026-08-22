# GitHub App deployment readiness

SynSec's hosted GitHub App modules are repository-security infrastructure, not a general-purpose target execution service. Production deployment must preserve the same fixed-host, commit-pinned, credential-minimized boundaries as the scan worker.

`@synsec/github/app-deployment` provides a preflight validator for operator-controlled settings that are easy to misconfigure before the bounded webhook handler is mounted. It intentionally validates configuration only; it does not open sockets, provision certificates, fetch secrets, modify firewall rules, or widen repository authorization.

## Preflight contract

Call `validateGitHubAppDeployment()` before starting the listener and fail startup when `ready` is false. `assertGitHubAppDeploymentReady()` is provided for callers that prefer an exception-based startup guard.

The preflight currently requires:

- a positive integer GitHub App id;
- a PEM-shaped App private key;
- a webhook secret of at least 32 UTF-8 bytes;
- a host/IP value rather than a URL-shaped listener setting;
- local TLS or explicit upstream TLS termination for any non-loopback listener;
- absolute durable-state and repository-workspace paths; and
- separate, non-nested state and workspace directory trees.

Plain HTTP is accepted only on loopback so local development can mount the handler without pretending that an externally reachable plaintext listener is production-ready.

Diagnostics are categorical and deliberately do not echo private keys, webhook secrets, token values, repository credentials, or filesystem contents. Startup logs may record issue codes, but operators should still avoid dumping the original configuration object.

## Example

```ts
import { assertGitHubAppDeploymentReady } from "@synsec/github/app-deployment";

assertGitHubAppDeploymentReady({
  appId: process.env.SYNSEC_GITHUB_APP_ID ?? "",
  privateKey: process.env.SYNSEC_GITHUB_APP_PRIVATE_KEY ?? "",
  webhookSecret: process.env.SYNSEC_GITHUB_WEBHOOK_SECRET ?? "",
  listenHost: "127.0.0.1",
  tlsMode: "terminated-upstream",
  stateDirectory: "/var/lib/synsec/state",
  workspaceDirectory: "/var/lib/synsec/workspaces",
});
```

A reverse proxy or ingress that terminates TLS should forward only to a private/loopback listener and should preserve the exact webhook request body. SynSec verifies `X-Hub-Signature-256` over the original bytes, so middleware must not parse and reserialize the body before the bounded webhook handler receives it.

## What this does not certify

A successful preflight does **not** mean the hosted service is production-complete. Operators still need process/container isolation for scanner subprocesses, OS CPU/memory limits, outbound network policy, listener/server timeouts, health supervision, secret injection and rotation, log retention, and a transactional shared state backend before horizontally scaling across hosts.

The validator also does not test whether GitHub currently grants an installation the permissions needed for a specific operation. Runtime installation-token exchange remains authoritative for `contents:read`, `checks:write`, and optional `security_events:write` diagnostics.

## Secret rotation

Treat App private keys and webhook secrets as hosting credentials, never scanner inputs. Rotation should replace injected credentials through the deployment platform, restart or roll the listener/runtime in a controlled way, and avoid writing either secret into SynSec state, reports, queue records, scanner environments, or repository workspaces.

Webhook-secret rotation requires coordination with the GitHub App configuration because GitHub signs deliveries with the configured secret. Do not silently accept multiple indefinitely valid secrets as a convenience fallback; if an overlap window is implemented by a hosting layer, keep it explicit, bounded, and observable.

## Filesystem placement

Durable authorization/replay/queue state and repository workspaces must not be the same tree or ancestors of one another. This prevents checkout cleanup, scanner traversal, or workspace retention policy from reaching durable App authorization state, and prevents durable state from being exposed as repository scan input.

A shared parent is fine. For example, `/var/lib/synsec/state` and `/var/lib/synsec/workspaces` are separate sibling trees. `/var/lib/synsec` and `/var/lib/synsec/workspaces` are not.

## Bounded maintenance and retention

The local runtime exposes `runMaintenance()` for durable state that can be deleted safely without guessing whether a repository scan is active. One maintenance pass prunes expired webhook replay markers according to the replay store's configured retention and removes only terminal `failed` queue records that have remained unchanged past the failed-job retention window.

Failed-job retention defaults to 30 days, accepts only values from 1 hour through 180 days, and deletes at most 100 records per pass unless `retentionMaxDeletes` is explicitly configured. The cap itself is bounded to 1,000. Pending and leased jobs are never deleted by retention, regardless of age. Failed-job age is measured from the durable queue record's last modification time, which is refreshed when the job becomes failed, rather than from the original enqueue timestamp.

```ts
const runtime = await createLocalGitHubAppRuntime({
  // ...credentials, config, stateDirectory, workspaceRoot...
  failedJobRetentionMs: 14 * 24 * 60 * 60 * 1000,
  retentionMaxDeletes: 100,
});

const result = await runtime.runMaintenance();
```

Operators may invoke maintenance from their existing supervised process loop or an external scheduler. SynSec deliberately does not create its own background timer because service scheduling and lifecycle belong to the hosting layer.

Repository workspaces use ownership-based cleanup instead of an age sweep: failed acquisition removes its temporary workspace immediately, and workers clean acquired head/base workspaces after processing. SynSec does not recursively delete old `synsec-github-*` directories merely because their modification time is old, because that heuristic could race a legitimately long-running scan. If a process is killed before cleanup completes, orphan-workspace reconciliation remains a hosting/isolated-runtime concern until SynSec has a durable ownership marker that can prove a workspace is no longer active.

## Sanitized runtime status

`runtime.getStatus()` returns an aggregate-only snapshot that a hosting layer can safely adapt into a local health/readiness endpoint. It reports installation totals split by active/suspended and repository-selection mode, plus queue totals split by pending/leased/failed status.

The status contract intentionally excludes installation ids, account logins, repository names, commit SHAs, delivery ids, source paths, scanner output, credentials, and arbitrary durable-record fields. Durable stores are still fully parsed and validated before aggregation; malformed persisted state makes status collection fail rather than silently reporting a healthy snapshot.

This snapshot is diagnostic data, not an authorization decision. A hosting layer should treat successful status collection as evidence that local durable state can be read, while installation authorization and GitHub permission checks remain authoritative at dispatch/worker execution time.
