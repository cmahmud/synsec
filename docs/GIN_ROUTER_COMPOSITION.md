# Gin router composition

SynSec can derive bounded structural route evidence for a deliberately narrow subset of Go services using `github.com/gin-gonic/gin`.

## Accepted shape

The analyzer requires one unaliased Gin import, a direct root declaration using `name := gin.Default()` or `name := gin.New()`, and one-line route/group construction. Literal groups may be nested to a bounded depth:

```go
router := gin.Default()
api := router.Group("/api", requireUser)
jobs := api.Group("/jobs")
jobs.POST("/run", audit, runJob)
```

The final plain identifier in a route registration is treated as the handler. Preceding route callbacks and inherited plain-identifier group callbacks are retained separately as middleware attachment evidence.

Go lexical call-graph support is also bounded. SynSec recognizes ordinary functions and methods with brace-delimited bodies, records direct same-file calls only when one unique function name exists, and resolves a Gin handler only when one unique Go function with that name exists in the same package directory. A route can therefore participate in exact sink correlation through its bounded same-file call neighborhood.

## Fail-closed cases

SynSec emits no composed Gin evidence for dynamic group prefixes, aliased Gin imports, router factories, member-expression or transformed handlers, transformed middleware, reassigned router/group bindings, ambiguous same-package handler names, unsafe/symlinked/oversized files, unsupported syntax, or composition beyond configured bounds.

Same-package resolution is a directory-level structural approximation. SynSec does not infer build tags, generated files, module replacement behavior, runtime registration order, or whether a particular binary includes the analyzed files.

## Security interpretation

Gin route evidence is static repository evidence only. `structural-route-call-sink-evidence-only` does not establish runtime reachability, attacker control, exploitability, or effective authorization. `structural-gin-route-middleware-attachment-not-runtime-protection` records only that middleware identifiers are syntactically attached through accepted Gin route/group forms; it does not prove Gin executes them or that they successfully protect a request.

Repository content remains untrusted. Source reads are bounded and confined to regular non-symlink files inside the supplied repository root. Dynamic or ambiguous shapes are omitted rather than guessed.
