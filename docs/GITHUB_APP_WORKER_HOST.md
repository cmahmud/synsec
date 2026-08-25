# GitHub App worker host

SynSec now has a separate executable worker role for durable GitHub App scan jobs. It is intentionally distinct from the webhook intake role.

## What is enforced

`@synsec/github/app-worker-host` composes the following boundaries in one process:

- exact secret-free host-profile validation;
- exact built-in PostgreSQL backend/conformance-evidence validation before credential or database access;
- mounted GitHub App credentials held only in the existing memory-only atomic credential source;
- serialized PostgreSQL migration plus shared installation authorization and fenced scan queue state;
- worker admission drain before `queue.claimNext()`;
- durable lease heartbeat, compare-and-set fence checks, and fenced terminal transitions;
- repository authorization recheck after lease acquisition;
- short-lived purpose-scoped installation tokens for acquisition and publication;
- exact queued commit acquisition into the operator-owned workspace tree;
- scanner execution through the digest-pinned OCI sandbox path;
- fresh publication authorization only after the worker still owns the durable lease.

The executable command is:

```sh
npm run github-app:worker-host -- --profile /absolute/host.json --conformance /absolute/postgres-conformance.json --config /absolute/worker-synsec.json
```

The PostgreSQL connection value is read only from the environment-variable name declared in the host profile. It is not accepted in the JSON profile.

## Current scanner scope

The production worker **fails closed unless every configured scanner is one of `checkov`, `grype`, or `syft`**.

This is not a product-level claim that those scanners are sufficient. They are currently the adapters whose availability and scan execution both support SynSec's enforced OCI process runner. Checkov adds offline IaC/configuration analysis to the hosted subset; its normal bundled checks do not require SynSec to grant scanner network access. The worker still refuses `opengrep`, `trivy`, `osv-scanner`, `scorecard`, or any other unsupported adapter in this role rather than silently executing it on the host.

The pinned scanner image must contain every selected tool. For Grype it must also contain all vulnerability database/cache material required by the pinned version. The OCI sandbox uses `network=none`; SynSec will not widen networking to make an unprepared scanner image succeed.

Changed-file Checkov scans remain bounded to validated repository-relative `-f` arguments and execute from the read-only `/workspace` repository root. Full Checkov scans map the configured repository directory into `/workspace` through the same OCI runner. Checkov exit code `1` remains its normal findings-present result; other non-zero exits fail the job.

AI review must also be disabled in the worker configuration. AI review is a separate outbound disclosure/trust boundary and is not part of scanner isolation.

## OCI boundary

For each exact acquired repository workspace, the worker constructs only OCI-backed adapters. The scanner sandbox enforces:

- immutable image digest pinning;
- repository bind mount read-only;
- container root filesystem read-only;
- separate bounded writable `/scratch` and `/tmp` tmpfs;
- numeric non-root UID/GID;
- all Linux capabilities dropped;
- `no-new-privileges`;
- bounded PIDs, memory, swap, and CPU;
- `network=none` and `ipc=none`;
- no host control socket or namespace mounts;
- no explicit scanner child environment.

GitHub installation tokens exist only in the host acquisition/publication layers. They are not mounted into the scanner container and are not passed as scanner environment variables.

## Async scanner composition

The normal local/CLI engine continues to use its ordinary built-in adapters. The hosted worker establishes a context-local scanner factory with `AsyncLocalStorage` for each scan operation. Concurrent worker operations therefore cannot replace one another's adapter set through process-global mutation.

That factory mechanism is only a composition primitive. It is **not isolation evidence by itself**. The worker's security property comes from supplying only the OCI-backed adapter factory and rejecting unsupported hosted scanner IDs before credentials or database migration are reached.

## Shutdown and rolling maintenance

`beginDrain()` closes local worker admission synchronously. New `runOnce()` calls then return `draining` before a queue claim can occur. Work admitted before the boundary closes keeps its existing durable lease and may complete normally.

`close()` begins drain and waits only for locally admitted worker calls. Fleet-wide stop eligibility still requires the existing durable PostgreSQL lease observer and maintenance/upgrade gates. A closed local worker does not prove another replica has stopped claiming work.

The executable process handles `SIGTERM` and `SIGINT` by closing worker admission, waiting for admitted local work, and then closing the PostgreSQL pool.

## Logging and disclosure

The executable loop emits only the release/replica identity at startup, the configured scanner IDs, and aggregate worker result categories. It deliberately does not print repository names, installation IDs, finding content, scanner diagnostics, installation tokens, private keys, webhook secrets, or database errors from individual jobs.

Operational code should continue treating all repository content, scanner output, GitHub responses, stored queue records, and backend diagnostics as untrusted.

## Interpretation

The worker reports the interpretation:

`executable-fenced-worker-with-enforced-oci-subset-not-fleet-readiness-or-complete-coverage`

A successful job therefore demonstrates that this worker used the configured transactional/fenced execution path and the currently supported OCI-isolated scanner subset. It does **not** prove fleet readiness, runtime reachability, exploitability, effective authorization beyond the explicit checks performed, complete scanner coverage, or absence of vulnerabilities.
