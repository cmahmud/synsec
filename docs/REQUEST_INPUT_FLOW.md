# Request-input flow evidence

SynSec can derive a narrow static relationship between explicit web-request input access and sensitive repository sinks. This layer is deliberately conservative. Its output is structural review context only and must not be interpreted as runtime reachability, attacker control, variable-level taint, exploitability, or proof that a deployed route is exposed.

## Evidence model

The repository analyzer records a request-input source only when source code contains an explicit supported request-access expression. Examples include Node-style `req.body`, `req.query`, `req.params`, headers, cookies and files; Koa/Hono-style request access; and bounded Flask/Django request access such as query, body, headers, cookies and files. Merely naming a parameter `request`, using an auth-looking identifier, declaring a route, or importing a framework does not create source evidence.

Request-input records contain only repository path, line, normalized input category, framework family, and a sanitized access category. They do not retain request values or arbitrary source-line text.

For a source to participate in a cross-function source-to-sink relationship, all of the following must hold:

1. The route has already resolved to one bounded lexical handler.
2. The request-access line belongs to exactly one lexical function in that route's bounded call neighborhood.
3. The sensitive sink line belongs to exactly one lexical function in the same bounded route neighborhood.
4. The explicit request access appears on the same source line as a resolved outbound call. SynSec does not infer that a local variable assigned on an earlier line remains request-controlled.
5. The sink-owning function is reachable from that source-bearing outbound call through bounded resolved same-file calls and, where applicable, explicit repository-local import bindings that resolve to one unique target function.

A same-function relationship is emitted only when the explicit request access and sensitive sink are on the exact same line. This avoids manufacturing local data-flow evidence from lexical function membership alone.

The emitted interpretation label is:

`structural-request-source-call-sink-evidence-only`

## Fail-closed behavior

SynSec omits this evidence when import resolution is ambiguous, function ownership is ambiguous, an import binding is shadowed, the route cannot be resolved conservatively, the request access is separated from the outbound call by an untracked local assignment, or the requested traversal exceeds configured file/node/evidence bounds.

For example, this does **not** create a source-to-sink relationship:

```ts
function handler(req) {
  const value = req.query.q;
  unrelated();
}

function unrelated() {
  db.query(sql);
}
```

Likewise, a handler that calls `consume(req.query.q)` and separately calls an unrelated sink-bearing function does not cause SynSec to associate the source with that sibling sink. Propagation begins only from the source-bearing call itself.

## Exact finding correlation

`findingRequestInputFlowEvidence()` returns minimized request-flow context only when a finding path and start line exactly match a sink line already linked by the structural source/call/sink analysis. Nearby findings are not upgraded merely because a related route or source exists elsewhere in the file.

The correlated metadata contains route identity, handler, source category/function, sink category/function, bounded call distance and whether explicit local imports were used. It excludes source excerpts and request/scanner values.

## Resource and trust boundaries

Repository contents, file metadata and imported names are untrusted input. Request-input analysis operates only on the already bounded repository file inventory, rejects path escape and symlink source entries, caps file size/count and signal volume, and never executes repository code or performs network access.

Scanner findings remain independent evidence. A request-input flow does not raise or suppress a scanner result by itself, and scanner-supplied metadata must not be treated as authoritative SynSec-derived flow evidence.

## Current limitations

This implementation intentionally does not provide SSA, AST-based taint propagation, alias analysis, object-property flow, sanitizer modeling, branch-sensitive control flow, interprocedural argument/return-value tracking, framework deployment resolution, or runtime instrumentation. Those capabilities should be added only when they can preserve the same fail-closed evidence semantics and resource bounds.
