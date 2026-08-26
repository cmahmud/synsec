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

## Directional request-input evidence

Strict Koa-composed handlers may also produce deliberately narrow request-input-to-sink evidence. The handler's first plain identifier parameter is treated as the structural Koa context only for an exact resolved `Koa router` entrypoint.

Direct evidence recognizes request-side access through `ctx.request.body`, `ctx.query`, `ctx.request.query`, `ctx.params`, `ctx.headers`, `ctx.request.headers`, `ctx.get(...)`, and `ctx.cookies.get(...)` when that access occurs on the exact sink line or on the same line as one resolved direct call to the sink-owning function. `ctx.body` is excluded because Koa uses it as response state.

A separate one-local forwarding layer recognizes only an exact immutable assignment followed by one unchanged single-argument use, for example:

```ts
function createUser(ctx) {
  const command = ctx.request.body.command;
  execute(command);
}

function execute(command) {
  child_process.exec(command);
}
```

The local must be declared with `const`, have exactly one later occurrence in the handler, remain within the configured forward-line bound, and be passed unchanged as the sole argument of an exact call. Multiple use, reassignment-capable `let`/`var`, transformation, aliasing, destructuring, object spreading, middleware propagation, and deeper forwarding fail closed.

For database evidence the Koa directional layers are stricter than the generic lexical sink index: the sink line must contain member-qualified database-style syntax such as `db.query(...)` or `client.execute(...)`. Bare local helpers named `query` or `execute` are not promoted into database flow merely because their names look sink-like.

Direct evidence uses `structural-koa-context-source-direct-call-sink-evidence-only`. One-local forwarding uses `structural-koa-context-source-single-use-local-call-sink-evidence-only`. Finding correlation returns source/sink categories and function identities without serializing request keys or source expressions.

## Fail-closed cases

The Koa model intentionally produces no composed or directional evidence for ambiguous or unsupported shapes, including:

- dynamic or computed router prefixes;
- Router import aliases or multiple competing Router bindings;
- router factories instead of direct `new Router(...)` construction;
- reassigned router variables;
- inline callbacks, member-expression handlers, middleware factories, or transformed callback expressions;
- ambiguous same-file or imported handlers;
- unsupported HTTP registration syntax;
- request aliases, destructuring, transformations, multi-use locals, mutable local bindings, wider propagation, or unsupported call shapes;
- generic Node routes that merely happen to use a `ctx`-looking parameter;
- unsafe, symlinked, oversized, or out-of-root repository files.

Output, file reads, forward distance, evidence count, and call-neighborhood traversal remain bounded by repository route-flow analysis limits.

## Security interpretation

Koa route and directional request evidence are static repository structure only. They do **not** prove that:

- the router is mounted into a running Koa application;
- a deployment exposes the route externally;
- attached middleware executes or successfully authenticates/authorizes a request;
- a request value is attacker controlled;
- a value reaches a sink at runtime;
- a value is or is not sanitized;
- a sink is runtime reachable; or
- a correlated finding is exploitable or non-exploitable.

Middleware attachment uses the interpretation `structural-koa-route-middleware-attachment-not-runtime-protection`. Route/call/sink correlation continues to use the existing structural evidence labels.

This separation is intentional: repository syntax can improve review prioritization without being promoted into a runtime security claim.
