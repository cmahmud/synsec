# GitHub App service-manager maintenance boundary

SynSec exposes `@synsec/github/app-maintenance` to connect the enforced webhook and worker admission drains to a trusted service manager without pretending that local process counters are durable fleet state.

## Stop/restart sequence

A hosting process should create one maintenance controller with the same `app-drain` and `app-worker-drain` controllers used by the live webhook and configured worker paths. The caller also supplies `countActiveLeases()`, backed by the transactional shared-state backend rather than local memory.

Before an intentional service stop, restart, or replacement:

1. Call `prepareForServiceStop()`.
2. SynSec synchronously closes webhook admission and worker-run admission.
3. Already-admitted webhook requests and worker runs are allowed to finish. The maintenance controller does not cancel, steal, or rewrite their work.
4. After local admitted work reaches zero, SynSec repeatedly queries the caller-owned durable lease observer.
5. Stop eligibility is returned only after the observer reports exactly zero active fenced leases while both admission boundaries are still closed.
6. The external service manager may then stop or replace the process. SynSec itself does not invoke systemd, Kubernetes, Docker, or a cloud control plane.

If the deployment or restart is aborted before the process stops, call `resumeAdmission()` explicitly. Admission is never reopened automatically after an observation failure or timeout.

## Service-manager integration example

The service manager should expose a privileged local control path or process signal whose handler invokes `prepareForServiceStop()` and exits successfully only when it returns stop evidence. The service manager can then use that helper as its pre-stop gate. Do not put database URLs, GitHub credentials, repository identities, webhook payloads, or scanner output into the control request.

For systemd, a deployment can place a small operator-owned helper in `ExecStop=` or `ExecStopPre=` that talks only to a loopback/Unix-domain administrative endpoint implemented by the hosting process. For Kubernetes, the equivalent integration belongs in a `preStop` lifecycle hook plus readiness removal. These are deployment examples, not claims that SynSec itself controls either service manager.

The service manager must use a stop timeout longer than SynSec's configured maintenance timeout. A timeout should fail closed and leave admission closed; the operator must decide whether to resume or investigate durable work instead of forcing a normal rolling restart.

## Durable lease observer boundary

`countActiveLeases()` is trusted hosting input. It must query the same transactional backend used for worker leases and return only a bounded non-negative integer. A local worker-run count, process table, readiness flag, or operator assertion is not a substitute.

Backend errors are deliberately reduced to a categorical maintenance error because driver diagnostics can contain connection strings, SQL, hostnames, tenant data, or other sensitive values. Invalid counts, including negative, fractional, non-finite, or unreasonably large values, also fail closed.

Zero durable leases is maintenance evidence only. It does not prove that all replicas in a deployment are drained. Multi-replica rolling upgrades must still use `app-upgrade` with exact fresh replica observations and closed worker admission on every expected replica.

## Trust and security interpretation

The maintenance controller enforces local admission closure through the existing drain controllers and requires a durable zero-lease observation before returning stop eligibility. It does not prove GitHub-side credential activation, scanner isolation, repository safety, runtime authorization, or absence of vulnerabilities. It also does not perform process termination, deployment, migration, rollback, or secret-manager operations.

Repository content, scanner output, webhook payloads, stored artifacts, backend errors, and externally supplied metadata remain untrusted. None may choose the lease observer or service-manager control path.
