# Route middleware composition evidence

SynSec performs a bounded static analysis of explicit Node HTTP router middleware composition to improve repository review context without claiming runtime protection.

## Supported shape

The analyzer accepts only one-line route registrations whose post-path arguments are plain identifiers, for example:

```ts
router.post("/users", requireSession, requireAdmin, createUser);
```

The final identifier is treated as the route handler and the preceding identifiers as middleware candidates. Invoked middleware factories, inline functions, member expressions, spreads, arrays, conditional expressions, and other dynamic forms are intentionally omitted.

Each middleware candidate resolves only when there is exactly one corresponding same-file function or one explicit repository-local ES named import/destructured CommonJS import with matching export evidence. Shadowed imported bindings, ambiguous functions, external modules, missing exports, and unresolved module targets remain unresolved.

## Bounded auth context

For resolved middleware functions, SynSec may collect authentication/authorization/session/token lexical signals from the middleware function and a bounded call neighborhood. Same-file calls and already-resolved explicit repository-local import calls can contribute evidence. Analysis is limited by route, depth, and node bounds and does not execute repository code or perform network access.

The resulting status is one of:

- `authorization-signal-observed`
- `authentication-signal-observed`
- `no-auth-signal-observed`

These labels are review signals only. They do not mean that middleware executes before the handler, that an authorization branch is effective, that a route is reachable, or that access control cannot be bypassed.

Every result is labeled:

`structural-route-middleware-evidence-not-runtime-protection`

## Fail-closed examples

SynSec deliberately emits no middleware composition for shapes such as:

```ts
router.get("/account", requireAuth(), handler);
router.get("/account", (req, res, next) => next(), handler);
router.get("/account", guards.admin, handler);
```

It also refuses to resolve an imported middleware binding if the local binding is reassigned or shadowed before the route registration.

This feature supplements, rather than replaces, route-to-handler, route-to-sink, request-input, and route-protection evidence. None of these static layers individually or collectively establish runtime reachability, attacker control, exploitability, or effective authorization.
