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

## Security interpretation

A resolved route-to-handler relationship means only that the repository contains a route registration and an unambiguous function declaration matching SynSec's conservative static rule. It must not be interpreted as any of the following:

- proof that the application starts or registers the route in production;
- proof that the route is internet-accessible;
- proof that authentication or authorization is present or absent;
- proof that a security-sensitive sink is reachable from attacker-controlled input;
- proof that an unresolved route is safe or unreachable; or
- permission to make network requests against the route.

Route authentication/sink proximity, call-graph edges, test coverage, dependency usage, and scanner findings remain separate evidence sources. Uncertainty in one source is not silently converted into certainty by another.

## Repository-first boundary

Route analysis reads only bounded files from the already-authorized repository checkout. It never launches the application, follows discovered URLs, probes HTTP listeners, sends scanner findings to live endpoints, expands to sibling repositories, or turns route strings into outbound targets.

Future framework-aware analysis should preserve these properties: bounded repository inputs, explicit ambiguity, evidence labels that distinguish static inference from runtime facts, and full fail-closed behavior when the framework shape cannot be resolved safely.
