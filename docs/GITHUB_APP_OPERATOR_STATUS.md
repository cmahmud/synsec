# Protected GitHub App operator status

`@synsec/github/app-operator-status` provides a small framework-free boundary for production operator diagnostics without widening the public GitHub webhook surface.

## Trust boundary

The endpoint is **not public health** and SynSec does not invent an operator identity system. Hosting code must provide `authorize(request)` using the deployment's existing protected operator plane (for example, mutually authenticated ingress, a service-mesh identity, or an authenticated internal admin gateway). An authorization failure or exception returns `404` and the observation callback is not invoked.

Only after authorization does `observe()` run. The observation contract is deliberately fixed and aggregate-only:

- bounded release identifier and schema version;
- readiness boolean;
- memory-only credential generation identifier, webhook-secret count, and reload count;
- webhook/worker admission state and local active counts;
- durable active fenced-lease count supplied by a trusted backend observer;
- categorical recovery phase;
- observation timestamp.

The response builder reconstructs every field. It does not spread caller objects, so arbitrary backend payloads, tenant identifiers, repository names, filesystem paths, scanner output, tokens, private keys, webhook secrets, or database diagnostics cannot accidentally become response fields.

## Failure behavior

Authentication failures are hidden as `404`. Observation failures return only `503 {"status":"unavailable"}`. The optional `onError` callback receives a new categorical error rather than the original exception, because secret-manager and database errors may contain credentials, connection strings, tenant data, or paths.

Responses set `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. The handler accepts only `GET` on one bounded absolute path; the default is `/_synsec/operator/status`.

## Interpretation

A successful response is labeled `aggregate-operator-observation-not-external-security-proof`. It is useful for authenticated operations tooling, but it does **not** prove:

- GitHub accepted the current App credential generation;
- repository or tenant authorization;
- fleet-wide readiness merely because one replica is ready;
- runtime reachability or scanner isolation beyond the separately enforced controls;
- exploitability or absence of vulnerabilities;
- successful service-manager rollout, recovery, or upgrade.

For multi-replica maintenance decisions, use the existing durable lease observer and upgrade/maintenance gates. For request authorization, use the installation/ownership/freshness boundaries rather than this diagnostic endpoint.
