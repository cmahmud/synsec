# Gin request-input flow evidence

SynSec exposes two deliberately narrow Go/Gin request-source analyses. Direct evidence is available through `@synsec/repository/gin-request-input-flow`; one-local forwarding evidence is available through `@synsec/repository/gin-request-input-forwarding`. The default `buildRepositoryRouteFlowAnalysis()` path produces both as `ginRequestInputFlows` and `ginRequestInputForwardingFlows`.

## Direct source-to-sink evidence

The direct analyzer can produce structural source-to-sink evidence only when all of these conditions hold:

- the source file is a bounded, regular, non-symlink `.go` file inside the repository root;
- the file imports `github.com/gin-gonic/gin` without an alias;
- the source-owning function declaration line contains exactly one explicit `*gin.Context` parameter;
- the source is one of the direct context accessors `Query`, `PostForm`, `Param`, `GetHeader`, or `Cookie` on that exact context binding;
- the access occurs on the exact sink line, or on the same line as a call-graph edge directly to the sink-owning function;
- the route has already been resolved as a Gin route by SynSec's existing bounded route and call analysis.

Direct evidence is labeled:

`structural-gin-context-source-direct-call-sink-evidence-only`

## Single-use local forwarding

The separate forwarding analyzer recognizes only a bounded shape equivalent to:

```go
term := c.Query("q")
runQuery(term)
```

The source accessor is limited to the single-value `Query`, `PostForm`, `Param`, and `GetHeader` methods. The local must be introduced with `:=`, have exactly one later identifier occurrence in the containing function, remain within the configured forward-line bound, and be passed unchanged as the sole argument of one exact call. That call must either be the sink line itself or resolve directly to the sink-owning function.

Forwarding evidence is labeled:

`structural-gin-context-source-single-use-local-call-sink-evidence-only`

This is evidence for one syntactically unchanged local hop. It is not a claim that Go locals are immutable by language semantics. Reassignment, a second use, aliasing, transformation, or another occurrence anywhere later in the function makes the analyzer fail closed.

Finding correlation for both layers is exact on the sink path and line. Request keys, values, source expressions, SQL text, and other repository content are not copied into finding evidence.

## Deliberate exclusions

These analyses are not a general Go taint engine. In particular, SynSec does not infer directional flow for:

- `ShouldBind`, `ShouldBindJSON`, `Bind`, `BindJSON`, or other APIs that populate an object through mutation;
- `Cookie` values stored in locals, because Gin's cookie accessor has multi-value return semantics;
- locals that are reassigned, used more than once, or forwarded beyond the configured line bound;
- transformed, concatenated, indexed, destructured, or aliased values;
- calls beyond one exact source-bearing outbound edge after the optional one-local hop;
- aliased or dot-imported Gin packages;
- values merely named `ctx`, `context`, `request`, or similar;
- custom types exposing methods named `Query`, `Param`, and so on;
- request-source-looking text outside a uniquely identified `*gin.Context` function.

Those cases require additional bounded data-flow semantics and are omitted rather than guessed.

## Security interpretation

A result is repository-structural review evidence. It does **not** prove:

- that Gin registers or serves the route in a running deployment;
- that the request value is attacker-controlled in a concrete execution;
- that middleware or authorization succeeds or fails;
- that a database/process/filesystem/network operation is exploitable;
- that sanitization is absent;
- that a missing result implies safety.

Use this evidence to prioritize review of an exact repository path, not as a runtime-security verdict.
