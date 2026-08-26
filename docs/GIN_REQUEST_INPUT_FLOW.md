# Gin request-input flow evidence

SynSec exposes a deliberately narrow Go/Gin request-source analysis through `@synsec/repository/gin-request-input-flow`. The same evidence is also produced by the default `buildRepositoryRouteFlowAnalysis()` path as `ginRequestInputFlows`, so callers do not need to invoke a separate analyzer to receive it.

## What it can establish

The analyzer can produce structural source-to-sink evidence only when all of these conditions hold:

- the source file is a bounded, regular, non-symlink `.go` file inside the repository root;
- the file imports `github.com/gin-gonic/gin` without an alias;
- the source-owning function declaration line contains exactly one explicit `*gin.Context` parameter;
- the source is one of the direct context accessors `Query`, `PostForm`, `Param`, `GetHeader`, or `Cookie` on that exact context binding;
- the access occurs on the exact sink line, or on the same line as a call-graph edge directly to the sink-owning function;
- the route has already been resolved as a Gin route by SynSec's existing bounded route and call analysis.

Evidence is labeled:

`structural-gin-context-source-direct-call-sink-evidence-only`

Finding correlation is exact on the sink path and line. Request keys, values, source expressions, SQL text, and other repository content are not copied into the finding evidence.

## Deliberate exclusions

This is not a general Go taint engine. In particular, SynSec does not infer directional flow for:

- `ShouldBind`, `ShouldBindJSON`, `Bind`, `BindJSON`, or other APIs that populate an object through mutation;
- a request value stored in a local and used on a later line;
- transformed, concatenated, indexed, destructured, or aliased values;
- calls beyond one exact direct source-bearing outbound edge;
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
