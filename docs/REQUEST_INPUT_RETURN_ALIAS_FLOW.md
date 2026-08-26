# Request-input helper return alias evidence

SynSec exposes a deliberately narrow supplemental repository-intelligence layer at `@synsec/repository/request-input-return-alias-flow`.

It recognizes only the structural shape where a JavaScript/TypeScript helper has exactly one direct `return req.<source>` statement, the helper result is assigned to `const`, that binding is used exactly once to initialize one second `const` alias, and the alias is then used exactly once as the sole unchanged argument to one uniquely resolved call on a bounded route-to-sink path.

For example:

```ts
function readName(req) {
  return req.body.name;
}

function createUser(req) {
  const name = readName(req);
  const persistedName = name;
  persistName(persistedName);
}
```

The evidence is labeled `structural-request-source-return-two-immutable-bindings-call-sink-evidence-only` and records `bindingHops: 2`. It is separate from the existing direct-binding return-flow evidence so consumers can distinguish the additional static inference.

## Fail-closed boundary

The analyzer emits no evidence when it sees a transformed value, a `let`/`var` binding, a second alias hop, mutation, multiple uses of either binding, multiple or conditional helper returns, destructuring, nested expressions, an unresolved or ambiguous call, unsupported Python flow, unsafe/symlinked/oversized files, or forwarding outside the configured line bound.

Repository-local explicit import edges may participate only when the existing import-call resolver resolves them uniquely. Import relationships are structural evidence and are not proof that a deployment executes the code.

## Security interpretation

This layer does **not** establish runtime reachability, attacker control, sanitization status, exploitability, successful framework registration, or authorization. It does not implement a general taint engine and must not be used to claim that a sink is exploitable merely because this structural pattern exists.

Finding correlation remains exact: sanitized evidence is returned only when the finding path and line exactly match the structurally linked sink line.
