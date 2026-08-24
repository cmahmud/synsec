# Structural route security review context

`@synsec/repository/route-security-review` joins SynSec's already-resolved route-to-sink and route-protection evidence into a minimized route-level review surface.

The API is intentionally conservative. It emits a record only for a route with linked sensitive-sink evidence. A protection status is accepted only when exactly one protection context matches the same route and resolved handler. Missing or duplicate protection records become `not-assessed` rather than being guessed.

The resulting signals are descriptive review labels:

- `sensitive-sink-with-authorization-signal`
- `sensitive-sink-with-authentication-signal`
- `sensitive-sink-without-auth-signal`
- `sensitive-sink-auth-context-unavailable`

They are not vulnerability severities and must not be used as proof that a route is deployed, public, attacker-controlled, protected, exploitable, or safe. `no-auth-signal-observed` means only that SynSec did not observe one in its bounded structural neighborhood.

## Composition

`buildRepositoryRouteFlowAnalysis()` now returns `routeSecurityReviews` alongside the bounded call graph, explicit import-call links, route entrypoints, route-to-sink flows, and route-protection contexts. This keeps the route-security join on the same filesystem and ambiguity boundaries as the underlying repository analysis instead of asking consumers to reimplement it.

The local `@synsec/dashboard` may also accept those review contexts. It validates them through `summarizeRouteSecurityReviews()` and renders aggregate counts only. Route strings, handler names, framework hints, source paths, source evidence, scanner diagnostics, and credentials are not copied into the dashboard index.

`summarizeRouteSecurityReviews()` treats supplied contexts as untrusted runtime data. It rejects inconsistent protection-status/signal pairs, unknown or duplicate sink kinds, unsupported interpretations or call scopes, invalid bounded identity metadata, and collections above 5,000 contexts. Its output contains only aggregate signal and sink-kind counts plus the number needing auth-context review.

## Disclosure and interpretation boundary

The route-level context deliberately excludes source lines, auth evidence text, sink evidence text, file paths, scanner diagnostics, credentials, and arbitrary outbound URLs. It contains only the route/method, optional framework hint, resolved handler name, sink kinds, aggregate protection status, call scope, and the interpretation `structural-route-security-review-context-only`.

The aggregate summary is narrower still and is labeled `aggregate-structural-route-security-review-only`. Neither representation changes finding severity, suppresses scanner evidence, authorizes remediation, or claims runtime reachability or protection.

This API performs no network access, executes no repository code, and does not broaden scan targets. It is intended for local dashboards, review queues, finding enrichment, and reporting surfaces that need compact security-review context without copying evidence-bearing source text.
