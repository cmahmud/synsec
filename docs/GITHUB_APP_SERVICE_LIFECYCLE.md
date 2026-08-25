# GitHub App service lifecycle integration

`@synsec/github/app-service-lifecycle` bridges trusted process/service-manager stop requests into SynSec's enforced maintenance boundary.

The lifecycle controller does **not** decide that a service may stop from a signal alone. A stop request first calls `prepareForServiceStop()`, which closes webhook and worker admission, waits for locally admitted work, and requires the configured durable lease observer to report zero current fenced leases. Only then is the caller-owned `onReadyToStop` callback invoked.

## Signal handling

`bindSynSecGitHubAppServiceSignals()` binds `SIGTERM` and `SIGINT` to the same serialized stop path. It deliberately does not call `process.exit()`, invoke systemd, patch a Kubernetes object, or terminate another process. The hosting application owns that final handoff.

A typical host should:

1. construct the webhook and worker drain controllers;
2. construct `createSynSecGitHubAppMaintenanceController()` with a durable lease observer, using the PostgreSQL observer for the built-in shared backend;
3. construct `createSynSecGitHubAppServiceLifecycleController()`;
4. bind `SIGTERM`/`SIGINT`;
5. in `onReadyToStop`, perform only the trusted local hosting action needed to finish process termination.

Concurrent stop requests are serialized. Once stop eligibility has been handed off successfully, the lifecycle cannot be resumed. If maintenance or the hosting handoff fails, the lifecycle enters `stop-failed`; an operator-controlled recovery path may call `resume()` to reopen webhook and worker admission.

## systemd boundary

For systemd, configure the process to receive `SIGTERM` and set `TimeoutStopSec` longer than SynSec's configured lifecycle timeout. The Node host installs the lifecycle signal binding. SynSec performs the drain/evidence check in-process; systemd remains responsible for process supervision and final termination.

Do not use a short `TimeoutStopSec` that can kill the process before fenced work drains. Do not interpret receipt of `SIGTERM` as evidence that shared-state leases are zero.

## Kubernetes boundary

For Kubernetes, the container receives `SIGTERM` during pod termination. The same lifecycle binding should begin the SynSec drain. `terminationGracePeriodSeconds` must exceed the configured lifecycle timeout plus expected shutdown overhead.

Readiness should be withdrawn when admission is drained so new traffic is not intentionally directed to the pod. A preStop hook may initiate an operator-owned drain endpoint only if that endpoint is authenticated and cannot be reached by repository content, scanner output, or public webhook traffic; signal-driven in-process draining avoids creating such an endpoint.

The lifecycle result proves only the local process admission state plus the durable lease observation supplied to its maintenance controller. It does not prove load-balancer propagation, pod deletion, rollout completion, or the state of other replicas.

## Disclosure boundary

Maintenance/backend exceptions and hosting callback failures are converted to categorical `stop-failed` state. Original errors are not returned through the lifecycle API because they may contain PostgreSQL URLs, filesystem paths, tenant data, command lines, or service-manager diagnostics.

Repository content, scanner output, webhook payloads, and externally supplied metadata must never supply the maintenance controller, durable lease observer, lifecycle callbacks, or signal source.
