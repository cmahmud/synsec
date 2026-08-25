# Koa router composition

SynSec provides a deliberately bounded structural model for Koa routes registered through `@koa/router` or the legacy `koa-router` package.

## Accepted shape

The analyzer recognizes only an unaliased `Router` import or CommonJS require, a `const` router constructed directly with `new Router()`, and an optional literal `prefix`:

```ts
import Router from "@koa/router";

const router = new Router({ prefix: "/api" });

function requireUser(ctx, next) {
  return next();
}

function createUser(ctx) {
  saveUser(ctx.request.body);
}

router.post("/users", requireUser, createUser);
```

For this shape SynSec can create structural route evidence for `POST /api/users`. The final plain-identifier callback is the handler. Earlier plain-identifier callbacks are retained separately as route middleware attachment evidence.

Same-file handlers are resolved against the bounded lexical call graph. An unresolved handler may subsequently resolve through SynSec's existing explicit repository-local named-import resolver when there is exactly one supported import binding, one target function, and matching export evidence.

## Fail-closed cases

The Koa model intentionally produces no composed evidence for ambiguous or unsupported shapes, including:

- dynamic or computed router prefixes;
- Router import aliases or multiple competing Router bindings;
- router factories instead of direct `new Router(...)` construction;
- reassigned router variables;
- inline callbacks, member-expression handlers, middleware factories, or transformed callback expressions;
- ambiguous same-file or imported handlers;
- unsupported HTTP registration syntax;
- unsafe, symlinked, oversized, or out-of-root repository files.

Output and call-neighborhood traversal remain bounded by the repository route-flow analysis limits.

## Security interpretation

Koa route evidence is static repository structure only. It does **not** prove that:

- the router is mounted into a running Koa application;
- a deployment exposes the route externally;
- attached middleware executes or successfully authenticates/authorizes a request;
- a request value is attacker controlled;
- a sink is runtime reachable; or
- a correlated finding is exploitable or non-exploitable.

Middleware attachment uses the interpretation `structural-koa-route-middleware-attachment-not-runtime-protection`. Route/call/sink correlation continues to use the existing structural evidence labels.

This separation is intentional: repository syntax can improve review prioritization without being promoted into a runtime security claim.
