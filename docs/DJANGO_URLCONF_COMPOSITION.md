# Django URLConf include composition

SynSec can compose a bounded structural route identity through an explicit Django URLConf include such as:

```python
path("api/", include("accounts.urls"))
```

when the literal module name maps to exactly one supplied repository Python file and that target URLConf already contains a uniquely resolved function-view route. The composed identity can then participate in the existing exact route-to-sink and request-input/source correlation pipeline.

For example, a parent `path("api/", include("accounts.urls"))` and a child `path("users/", create_user)` can produce structural route evidence for `api/users/`. Nested literal includes are followed only to a bounded depth and the total number of composed routes is bounded.

## Fail-closed boundary

The composition layer does not import or execute repository Python code. It follows only literal `include("module.name")` values that map to exactly one supplied `module/name.py` or `module/name/__init__.py` file. Ambiguous module files, dynamic include expressions, callable include targets, tuple/list URLConfs, cycles without a structural root, unsafe files, symlinks, and inputs beyond the configured bounds do not produce composed evidence.

Existing direct child entrypoints are intentionally retained. Static repository analysis cannot prove which URLConf Django selects as `ROOT_URLCONF`, whether a URLConf is mounted in more than one deployment configuration, or whether a repository fragment is active at runtime.

## Security interpretation

A composed Django route is labeled as `Django URLConf include` structural evidence. It is **not** proof of:

- `ROOT_URLCONF` selection or Django settings activation;
- execution of `include()` or namespace behavior;
- middleware execution or effective authorization;
- runtime or attacker reachability;
- exploitability or absence of a vulnerability.

The feature exists to make repository review and exact finding correlation more useful without converting static URL relationships into runtime security claims.
