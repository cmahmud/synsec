# Express router composition

SynSec performs a bounded structural analysis for a narrow subset of Express router mounting so repository findings can retain exact route context across files.

Supported shapes include explicit `express()` application roots, explicit `express.Router()` or unaliased `Router()` router declarations, literal `app.use("/prefix", childRouter)` / `router.use("/prefix", childRouter)` mounts, and repository-local default imports or CommonJS `require()` bindings whose target exports exactly one router as the module default value.

For a successfully resolved chain such as `app.use("/api", usersRouter)` plus `router.get("/users/:id", getUser)`, SynSec may emit a composed `/api/users/:id` structural entrypoint while preserving the already-resolved handler and bounded call/sink evidence.

## Fail-closed cases

No composed evidence is emitted for dynamic prefixes, router factories, member-expression child routers, unresolved or ambiguous module edges, non-default export shapes, shadowed imported bindings, use-before-declaration, cycles beyond the configured bound, unsafe/symlinked files, or unsupported multiline/dynamic registration forms.

The default mount-depth bound is 8 and can be lowered through `maxExpressMountDepth`; composed output is separately bounded through `maxExpressComposedRoutes`.

## Security interpretation

The composition label is `structural-express-router-composition-not-runtime-reachability`.

It is evidence about source structure only. It does not prove that Express loads the module, executes the mount, serves the route, preserves the observed middleware order, makes the route externally reachable, accepts attacker-controlled input, or is exploitable or non-exploitable. Runtime deployment configuration and authorization remain separate trust boundaries.
