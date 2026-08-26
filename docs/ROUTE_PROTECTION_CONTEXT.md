# Structural route protection context

SynSec can correlate auth-related lexical signals with a resolved repository route and its bounded call neighborhood. This context is intended to help reviewers prioritize findings that are structurally connected to HTTP routes without turning static names into an authorization verdict.

The analysis is available from `@synsec/repository/route-protection-context` and is also composed by `buildRepositoryRouteFlowAnalysis()`.

## What is considered

For an already-resolved route entrypoint, SynSec can consider:

- authentication or authorization signals on the exact route-registration line, such as a plainly named middleware identifier;
- auth-related signals located inside the resolved handler function;
- auth-related signals inside bounded same-file callees; and
- auth-related signals inside a repository-local imported callee only when the existing import/call analysis resolves that binding to one unique lexical function.

The output omits source text. Evidence records contain only repository path, line, signal kind, structural source, and—when applicable—the owning function name and call depth. Finding-level correlation is even smaller: it reports only the route identity, handler, aggregate status, observed signal kinds, and call scope.

## Scan-engine enrichment

The normal scan engine consumes the composed route-protection contexts alongside route-to-sink flows. For a non-secret finding, `metadata.routeProtection` is attached only when the finding's normalized repository path and exact start line already match sink evidence in a resolved structural route flow.

The report-level metadata is deliberately minimized. It does not include source lines, auth-signal paths, auth function names, scanner diagnostics, or scanner evidence. Secret findings remain outside repository-context, route-flow, and route-protection enrichment entirely.

Route-protection metadata is contextual review evidence only. The engine does not use it to change severity, confidence, baseline state, failure thresholds, lifecycle state, remediation approval, or publication eligibility. In particular, `authorization-signal-observed` must never suppress a scanner finding, and `no-auth-signal-observed` must never be promoted into an exploitability claim.

## Fail-closed behavior

SynSec does not manufacture route protection when resolution is ambiguous. Unresolved route handlers, ambiguous function ownership, unsupported dynamic calls, unlinked imports, and auth-looking signals outside the bounded route/call neighborhood are omitted.

A finding receives route-protection context only when its exact normalized path and start line already match sink evidence in a structural route flow. This keeps auth context tied to the same conservative route-to-sink relationship instead of attaching nearby auth words to unrelated findings.

## Interpretation boundary

The status values are deliberately phrased as observations:

- `authorization-signal-observed`
- `authentication-signal-observed`
- `no-auth-signal-observed`

They are **not** equivalent to “authorized,” “authenticated,” or “public.” Static analysis cannot prove that middleware executes, that checks are effective, that every branch enforces them, that the route is deployed, or that an attacker can reach the sink. Likewise, `no-auth-signal-observed` means only that SynSec did not observe supported structural auth evidence in the bounded scope; it is not proof that a route is unprotected.

The machine-readable interpretation is therefore always:

`structural-auth-signals-not-protection-proof`

This analysis performs no network requests, does not execute repository code, and does not authorize live route probing or target expansion.
