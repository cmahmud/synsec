# GitHub App recovery boundary

SynSec provides a process-local recovery admission gate through `@synsec/github/app-recovery`. It is intended for operators recovering a hosted GitHub App replica after a shared-state, runtime-credential, GitHub control-plane, or explicitly initiated operational incident.

## Enforced behavior

`isolate()` immediately closes both webhook and worker admission through the existing maintenance controller. Operations already admitted before isolation are not killed; their normal fenced queue ownership and terminal transitions remain authoritative.

`recover()` keeps admission closed until:

1. locally admitted webhook requests and worker runs have both reached zero;
2. a caller-owned trusted recovery probe reports, in one observation, that shared state, the active runtime credential source, and the GitHub control plane are ready; and
3. local admission is still closed immediately before SynSec reopens it.

Concurrent recovery calls inside one process are coalesced. Explicit `not ready` observations can be retried until the bounded recovery deadline. A thrown probe, malformed probe output, externally reopened admission, or timeout fails closed and leaves admission closed.

Probe exceptions are deliberately discarded. Recovery status contains only a categorical incident reason, attempt count, and the interpretation `local-admission-recovery-boundary-not-external-health-proof`; it does not expose database URLs, filesystem paths, GitHub responses, tenant identifiers, tokens, private keys, or secret-manager diagnostics.

## Trusted hosting boundary

The recovery probe belongs to trusted hosting code. Repository content, scanner output, webhook payloads, stored artifacts, CLI input, and externally supplied metadata must never construct the probe or decide its result.

A production probe should normally verify, using credential-owning infrastructure:

- the configured transactional shared-state backend can complete an appropriate non-destructive health operation and is on the expected schema generation;
- the currently selected runtime credential generation can be loaded and validated locally; and
- the GitHub App control-plane operation required by the deployment can complete with bounded timeouts and sanitized diagnostics.

The exact checks are deployment-specific. `true` is therefore operator/runtime evidence, not a security proof. In particular, `runtimeCredentialsReady` does not prove GitHub accepted newly rolled credentials unless the probe actually validates that property, and `githubControlPlaneReady` does not establish installation ownership or repository authorization.

## Multi-replica recovery

This controller is intentionally not a distributed recovery lock. A service manager or rollout controller must isolate and recover each replica according to deployment policy. SynSec's PostgreSQL fencing, installation authorization state, hosted ownership fence, and re-verification freshness checks remain the authoritative cross-replica controls.

Do not release hosted installation ownership, delete durable queue state, rewrite lease fencing tokens, or truncate replay state as a recovery shortcut. Those operations change security semantics and are not performed by the recovery controller.

## Suggested operator sequence

1. Detect the incident through trusted service/backend telemetry.
2. Call `isolate()` with only the corresponding categorical reason.
3. Repair or roll back the failing infrastructure outside SynSec.
4. Call `recover()` with a bounded deadline.
5. If recovery succeeds, allow the service manager to continue normal operation.
6. If recovery fails, keep the replica isolated and investigate through protected operator logs. Do not surface raw backend/GitHub/secret-manager diagnostics through user-facing status endpoints.

A successful recovery means only that this process enforced its local drain/reopen sequence and the configured trusted probe reported ready. It does not prove that another replica recovered, that an upgrade completed, that GitHub will accept every future request, or that repository code is safe.
