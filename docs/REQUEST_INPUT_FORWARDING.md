# Bounded request-input forwarding

SynSec's request-input forwarding analysis adds one deliberately narrow data-flow step on top of direct request-access evidence. It exists to cover a common repository pattern without turning lexical heuristics into a general taint engine.

## What is recognized

The forwarding layer currently applies only to JavaScript and TypeScript source. A candidate must have all of these properties:

- The source is an explicit request access already recognized by SynSec, such as `req.body`, `req.query`, or `req.params`.
- The exact source line is a simple `const` declaration whose right-hand side is only a supported request access plus direct property or literal-key selection.
- The local binding has exactly one later use in the same lexical function within the configured line bound.
- That use passes the binding unchanged as a direct argument to a call.
- The call resolves to exactly one repository-local function through either the lexical same-file call graph or one explicit unique import binding.
- From that target, the bounded route call neighborhood reaches a sink already identified by SynSec.
- Exact finding correlation is performed only against the already-linked sink line.

The resulting interpretation string is:

`structural-request-source-immutable-binding-call-sink-evidence-only`

## What deliberately fails closed

SynSec omits forwarding evidence for reassignment or mutation, destructuring, multiple uses, transformations such as `normalize(value)`, nested call arguments, alias chains, sanitizer or validator steps, unresolved/external calls, ambiguous local targets, Python assignments, dynamic dispatch, and evidence outside the bounded route call neighborhood.

This conservative behavior is intentional. In particular, a sanitizer-looking function is not assumed to sanitize data, and a request-looking variable name is not assumed to be attacker-controlled.

## Security interpretation

This is structural static evidence. It does **not** prove runtime reachability, attacker control, effective validation, exploitability, successful injection, authorization bypass, or vulnerability absence. The repository contents being analyzed are untrusted input; source text and local variable names are not copied into the exported evidence object.

The older direct request-input flow remains a separate evidence layer. SynSec does not silently broaden its semantics: same-line direct source-to-call evidence and immutable-local-forwarding evidence have distinct interpretation labels and can be reviewed independently.
