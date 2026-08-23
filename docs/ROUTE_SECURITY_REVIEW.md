# Structural route security review context

`@synsec/repository/route-security-review` joins SynSec's already-resolved route-to-sink and route-protection evidence into a minimized route-level review surface.

The API is intentionally conservative. It emits a record only for a route with linked sensitive-sink evidence. A protection status is accepted only when exactly one protection context matches the same route and resolved handler. Missing or duplicate protection records become `not-assessed` rather than being guessed.

The resulting signals are descriptive review labels:

- `sensitive-sink-with-authorization-signal`
- `sensitive-sink-with-authentication-signal`
- `sensitive-sink-without-auth-signal`
- `sensitive-sink-auth-context-unavailable`

They are not vulnerability severities and must not be used as proof that a route is deployed, public, attacker-controlled, protected, exploitable, or safe. `no-auth-signal-observed` means only that SynSec did not observe one in its bounded structural neighborhood.

The summary deliberately excludes source lines, auth evidence text, sink evidence text, file paths, scanner diagnostics, credentials, and arbitrary outbound URLs. It contains only the route/method, optional framework hint, resolved handler name, sink kinds, aggregate protection status, call scope, and the interpretation `structural-route-security-review-context-only`.

This API performs no network access, executes no repository code, and does not broaden scan targets. It is intended for local dashboards, review queues, and future finding-enrichment/reporting surfaces that need a compact security-review signal without copying evidence-bearing source text.
