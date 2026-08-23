# GitHub App shared-state evidence gate

SynSec can validate portable shared-state conformance evidence before an operator treats a horizontally scaled GitHub App deployment as ready for review.

The gate is intentionally offline and credential-free. It does not connect to PostgreSQL or another database, contact GitHub, certify a backend, or accept connection strings. It only verifies that a versioned backend contract and a conformance report are structurally valid, complete, untampered, and bound to the exact same adapter identity and implementation version.

## CLI

```bash
synsec-github-app-evidence backend-contract.json conformance-report.json
```

Use `--json` for deployment and CI policy:

```bash
synsec-github-app-evidence backend-contract.json conformance-report.json --json
```

Exit codes:

- `0`: the supplied artifacts pass the evidence-binding gate.
- `2`: the artifacts are parseable but do not establish readiness, for example because conformance is incomplete, the backend identity differs, or the implementation version is stale.
- `1`: usage, file, size, JSON parsing, or unsupported arguments failed.

The command bounds each input file to 1 MiB, rejects unknown/duplicate flags instead of silently ignoring operator typos, and does not include backend-provided error text in its assessment. Invalid credential-shaped values are rejected by the underlying contract validator without being echoed into the portable result.

## What the gate verifies

The gate independently checks all of the following instead of trusting summary flags supplied by an adapter:

1. The backend contract uses SynSec's supported contract schema and declares every required shared-state capability.
2. Every capability has one bounded, secret-free implementation evidence entry.
3. The conformance report has the supported schema and one result for every canonical adversarial scenario.
4. Scenario identifiers are canonical and unique.
5. Result status and duration values are bounded and valid.
6. Derived coverage matches the actual scenario results.
7. Every required scenario passed.
8. `backendId` and `implementationVersion` exactly match between the contract and report.

A successful result is therefore suitable as a deployment-review prerequisite, but it is not database certification. The conformance report still has to be produced by a harness that exercised the real backend using genuine concurrent independent connections or processes.

## Composed production readiness

Application code can use `assessGitHubAppProductionReadiness()` from `@synsec/github/production-readiness` to compose the ordinary hosted deployment preflight with the shared-state evidence gate.

For one application replica, production readiness preserves the existing deployment-preflight semantics. For more than one replica, capability declarations alone are insufficient: readiness additionally requires a structurally valid, complete conformance report bound to the exact backend adapter build. Missing evidence therefore fails closed even when every transactional capability flag is declared true.

`assertGitHubAppProductionReady()` exposes the same policy as an assertion suitable for startup/provisioning code. Its failure message contains categorical issue codes only; backend contract values, database errors, credentials, and connection details are not included.

This composition is designed to prevent a deployment pipeline from accidentally treating `shared-transactional` plus seven boolean capability declarations as proof that a backend has actually passed SynSec's adversarial concurrency contract.

## Defensive boundary

This workflow only evaluates repository-hosting infrastructure for SynSec itself. It does not authorize scanning additional repositories, grant GitHub permissions, inspect repository source, perform network assessment, or enable any live-target exploitation behavior.
