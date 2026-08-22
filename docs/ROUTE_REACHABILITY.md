# Route and handler reachability evidence

SynSec records bounded static route and call-graph evidence to help reviewers prioritize repository findings. This evidence is structural only. It does not prove that a route is deployed, externally reachable, reachable by an attacker, or executable in a particular production configuration.

## Route detection

The repository index recognizes a deliberately small set of route-registration shapes without executing repository code. Existing decorator-style Python and TypeScript/JavaScript route signals remain supported. Node route signals recognize literal-path registrations on `app`, `router`, or `server` for common HTTP methods.

For Node registrations, SynSec records a named-handler candidate only when the complete single-line registration after the literal path is a comma-separated list of plain identifiers, for example:

```ts
router.get("/users", requireAuth, listUsers);
```

Here `listUsers` may be recorded as the handler candidate. The preceding `requireAuth` identifier is not treated as proof that the route is authenticated; authentication remains separate lexical evidence.

SynSec deliberately does **not** infer a named handler from registrations containing inline functions, function-call expressions, member expressions, spreads, dynamically constructed paths, mounted routers, or other compound expressions. Examples such as these remain unresolved:

```ts
router.post("/users", (req, res) => createUser(req, res));
router.patch("/users/:id", requireAuth(), updateUser);
router.use("/admin", adminRouter);
```

This restriction is intentional. A broader regex would create misleading handler associations for framework composition that requires semantic execution or framework-aware analysis.

## Handler resolution

`resolveRouteEntrypoints()` can map a recorded Node named-handler candidate to the bounded lexical call graph only when exactly one function with that name exists in the same repository file. Duplicate same-file declarations, missing declarations, imported handlers, and other ambiguity remain `unresolved`.

Decorator-style routes continue to use the existing bounded nearest-following-function rule. Both resolution paths are labeled `structural-route-call-evidence-only`.

For a resolved handler, SynSec may expose the existing bounded lexical call neighborhood. Those calls are still regex/lexical relationships. Dynamic dispatch, framework dependency injection, callbacks, aliases, imported functions, and runtime control flow can make the static neighborhood incomplete.

## Structural route-to-sink flow

`@synsec/repository/route-sink-flow` combines three already bounded repository signals: a resolved route entrypoint, its same-file lexical call neighborhood, and normalized sensitive-sink lines. A sink is linked to a route only when its line belongs to exactly one function in that bounded reachable node set. Ambiguous function containment is omitted rather than resolved heuristically.

The flow context contains only route identity, handler/function identity, sink category, line, and call depth. It deliberately excludes the sink source-line evidence stored in the repository index. The interpretation is always `structural-route-call-sink-evidence-only`.

The scan engine consumes this evidence conservatively. For non-secret findings, `metadata.routeFlow` is attached only when the finding's normalized repository path and exact start line match a linked sink line. A finding elsewhere in the same handler, file, or route neighborhood does not inherit route-flow metadata merely by proximity. Secret findings never receive this enrichment and remain on their narrower metadata boundary.

The engine builds the bounded call graph for this purpose only when the repository index contains both route and sink signals. This avoids an additional analysis pass for repositories where route-to-sink evidence cannot exist.

## Security interpretation

A resolved route-to-handler or route-to-sink relationship means only that the repository contains static structures matching SynSec's conservative rules. It must not be interpreted as any of the following:

- proof that the application starts or registers the route in production;
- proof that the route is internet-accessible;
- proof that authentication or authorization is present or absent;
- proof that attacker-controlled input reaches the sink;
- proof that the sink is executable on a real request;
- proof that an unresolved route is safe or unreachable; or
- permission to make network requests against the route.

Route authentication/sink proximity, route-flow metadata, call-graph edges, test coverage, dependency usage, and scanner findings remain separate evidence sources. Uncertainty in one source is not silently converted into certainty by another.

## Repository-first boundary

Route analysis reads only bounded files from the already-authorized repository checkout. It never launches the application, follows discovered URLs, probes HTTP listeners, sends scanner findings to live endpoints, expands to sibling repositories, or turns route strings into outbound targets.

Future framework-aware analysis should preserve these properties: bounded repository inputs, explicit ambiguity, evidence labels that distinguish static inference from runtime facts, and full fail-closed behavior when the framework shape cannot be resolved safely.
