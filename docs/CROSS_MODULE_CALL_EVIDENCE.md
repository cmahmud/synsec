# Cross-module call evidence

SynSec's lexical call graph deliberately resolves only unambiguous same-file function calls. Cross-module call evidence is a separate, stricter layer so repository intelligence can improve without turning import syntax into a claim of runtime reachability.

## Supported evidence

`@synsec/repository/import-call-links` can connect an unresolved lexical call to another indexed repository file only when all of the following are true:

1. the repository module graph already resolved the import to exactly one local file;
2. the source line contains an explicit supported import binding;
3. the call uses that exact local binding;
4. the imported function name maps to exactly one lexical function node in the resolved target file; and
5. the operation remains inside the configured file, source-size, binding, and link bounds.

The initial supported forms are deliberately narrow:

- JavaScript/TypeScript named imports, including `as` aliases;
- JavaScript/TypeScript namespace imports followed by one direct member call;
- CommonJS destructured `require()` bindings;
- Python `from ... import ...` bindings, including `as` aliases; and
- Python module imports followed by one direct member call when the module graph has already proven the module is repository-local.

Default imports, star imports, re-export chains, computed member access, nested member chains, dynamic import bindings, ambiguous local aliases, ambiguous target functions, and unresolved/external modules are omitted rather than guessed.

## Composed analysis

`@synsec/repository/route-flow-analysis` is the composition API for callers that need route-flow context. Given an existing repository index and module graph, it builds the bounded lexical call graph, explicit local import-call links, route entrypoints, and route-to-sink contexts using one consistent call-depth/node budget.

Before lexical source analysis, the composition layer independently revalidates the supplied file list against the repository root. It accepts only regular non-symlink files inside the root and uses the actual filesystem size instead of trusting caller-supplied size metadata. The aggregate result records `inputFileCount`, `analyzedFileCount`, `skippedUnsafeFileCount`, and `truncatedFileCount`.

File coverage is also explicit:

- `complete-input` means every supplied inventory entry was considered within the configured file-count bound, although unsafe entries may still have been rejected and are separately counted;
- `bounded-input` means one or more supplied inventory entries were outside the configured analysis bound and were not lexically analyzed.

The default and absolute `maxFiles` ceiling is 5,000. Callers may choose a lower positive bound, but invalid or excessive bounds fail closed instead of being silently clamped. A `bounded-input` result must not be presented as proof that the entire repository was analyzed. This is especially important for future engine or hosted integrations that use route-flow evidence for finding prioritization.

This preflight is defense in depth for integrations that do not obtain their file inventory through SynSec's normal repository walker. The composition API performs no network access and does not execute repository code. A caller is still responsible for passing an index and module graph derived from the same repository revision and inventory.

## Route-to-sink use

`@synsec/repository/route-sink-flow` may optionally consume the import-call graph. When it does, bounded route traversal can cross one of the explicit local import links and then continue through ordinary same-file lexical calls in the imported module.

Route-flow output records `callScope` as either:

- `same-file`; or
- `same-file-and-explicit-imports`.

Finding enrichment still requires an exact repository path and sink line match. Source text, import source text, scanner diagnostics, and credentials are not copied into the route-flow metadata.

## Security interpretation

All of this remains static structural evidence. The interpretation strings are intentionally explicit:

- `cross-module-import-call-evidence-only`;
- `repository-structural-route-flow-evidence-only`; and
- `structural-route-call-sink-evidence-only`.

A linked import/call does **not** prove that:

- the route is deployed or internet-accessible;
- a request can reach the call at runtime;
- attacker-controlled data reaches the sink;
- branch conditions permit the path;
- dependency injection or monkey-patching did not replace the target; or
- the sink is exploitable.

SynSec must not use this evidence to authorize live-target probing, exploitation, secret retrieval, persistence, or expansion beyond the repository scan target. Its purpose is defensive review prioritization and more useful repository-local context.
