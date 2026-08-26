# Koa request-input flow evidence

SynSec exposes a deliberately narrow Koa-specific request-source analysis for routes already resolved by the strict `@koa/router` / `koa-router` composer.

## What is recognized

A Koa route must first satisfy the existing router-composition constraints: one unaliased Router import/require, direct `const` router construction with an optional literal prefix, an unreassigned router binding, and plain-identifier callbacks. Koa-produced routes carry the distinct `Koa router` framework identity so they cannot be confused with generic Node router evidence.

For a resolved Koa route handler, SynSec treats only the handler's first plain identifier parameter as the structural Koa context. It recognizes these explicit accesses:

- `ctx.request.body` as body evidence;
- `ctx.query` or `ctx.request.query` as query evidence;
- `ctx.params` as path evidence;
- `ctx.headers`, `ctx.request.headers`, or `ctx.get(...)` as header evidence;
- `ctx.cookies.get(...)` as cookie evidence.

`ctx.body` is deliberately excluded because Koa uses that property for the response body rather than request input.

The access must occur either on the exact sink line or on the same line as one directly resolved call into the sink-owning function. Exact finding correlation returns only route/method, aggregate source and sink kinds, function names, and direct call distance. Request keys, values, and source text are not copied into finding evidence.

## Fail-closed exclusions

The Koa-specific layer intentionally does not infer flow through:

- locals assigned from request access and used later;
- aliases, destructuring, transformations, spreads, or member copies;
- middleware-to-handler context propagation;
- calls more than one direct edge beyond the source line;
- inline/dynamic router callbacks rejected by the Koa composer;
- generic Express/Node routes that merely use a variable named `ctx`;
- response-only properties such as `ctx.body`;
- unsafe paths, symlinks, oversized source files, or unsupported file types.

Those shapes require separate, bounded analyses. They are not silently promoted into a directional data-flow claim.

## Security interpretation

Every result is labeled `structural-koa-context-source-direct-call-sink-evidence-only`.

This means SynSec observed a strict Koa route shape, an explicit access on the structural handler context parameter, and an exact same-line sink or one direct resolved call to the sink-owning function. It does **not** prove that the router is mounted at runtime, the route is externally reachable, the value is attacker-controlled in a deployment, middleware executes, authorization is effective, sanitization is absent, or the sink is exploitable.
