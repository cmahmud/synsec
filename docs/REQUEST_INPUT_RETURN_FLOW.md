# Request-input helper return flow

SynSec has a deliberately narrow structural layer for one common repository pattern where a helper reads request input and returns it directly to a route-reachable caller:

```ts
function readName(req) {
  return req.body.name;
}

function createUser(req) {
  const name = readName(req);
  persistName(name);
}
```

The resulting evidence is labeled `structural-request-source-return-binding-call-sink-evidence-only`.

## What is accepted

The analyzer currently accepts only bounded JavaScript/TypeScript evidence where all of the following are true:

- the source is an explicit request access already recognized by SynSec;
- that source is the helper's only lexical `return` statement and the return expression is exactly a direct `req`/`request` body, query, path, header, cookie, or file access;
- the helper call resolves to exactly one same-file function or one explicit repository-local import target;
- the helper is called with one simple identifier and the result is assigned directly to a `const` binding;
- the binding has exactly one later lexical use in the caller;
- that use occurs within the configured line bound and is the only argument to one resolved direct call; and
- a route-linked sink exists on a bounded directed call path from that forwarding call.

Exact sink-line correlation is available through `findingRequestInputReturnFlowEvidence()`.

## Fail-closed cases

SynSec emits no return-flow evidence for transformed returns, multiple return statements, destructuring, `let`/`var` return bindings, aliasing, mutation, multiple uses, nested call expressions, unresolved or ambiguous calls, Python helpers, unsupported request syntax, oversized/unsafe source files, or values forwarded outside the configured bound.

Those omissions are intentional. They avoid turning a small structural feature into an unsound whole-program taint engine.

## Security interpretation

This evidence does **not** prove runtime reachability, attacker control, framework parameter binding, successful routing, sanitization or lack of sanitization, exploitability, or non-exploitability. Repository source, import relationships, request-looking identifiers, and scanner findings remain untrusted input.

The layer records a bounded lexical relationship that can improve review prioritization and exact finding correlation. Runtime security claims still require appropriate dynamic or operational evidence.
