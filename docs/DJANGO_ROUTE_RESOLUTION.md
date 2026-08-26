# Django URLConf structural resolution

SynSec can connect a narrow class of Django URL registrations to repository-local function views so existing route-to-sink, request-input, authorization-context, and exact finding-correlation analysis can continue past `urls.py`.

This is static structural evidence only. A resolved URLConf entry does not prove that Django loads the module, that the route is reachable in a deployed URL tree, that middleware executes, that a request value is attacker-controlled, or that a sink is exploitable.

## Supported shape

SynSec resolves only an explicit function identifier in a Django `path()` registration:

```python
from .views import create_user as create_user_view

path("users/", create_user_view, name="create-user")
```

The identifier must resolve uniquely to either:

- one Python function in the same URLConf file; or
- one unshadowed `from module import function [as alias]` binding whose module graph target is a unique repository-local Python file containing one matching function declaration.

The existing module-graph rules still apply. Relative imports must remain inside the supplied repository inventory. Absolute imports count as repository-local only when their first segment is an explicit top-level Python package in that inventory.

## Deliberately unresolved forms

SynSec fails closed for forms whose runtime meaning would require more interpretation than the current evidence model can justify, including:

- dotted members such as `views.create_user`;
- class-based views such as `AdminView.as_view()`;
- lambdas, wrappers, factories, and other call expressions;
- wildcard imports;
- parenthesized/multiline import lists;
- imports shadowed before the route registration;
- duplicate same-name local/imported candidates;
- missing, symlinked, oversized, or path-escaping source files;
- external or ambiguous module targets.

These cases remain `unresolved`; SynSec does not select a likely view.

## Downstream evidence

Once a view is resolved, the ordinary bounded call graph is used. This allows the same structural route evidence already used elsewhere in SynSec to include Django function views. For example, an explicit `request.POST` access passed directly into one resolved call can participate in the existing request-source/call/sink model, and a scanner finding can correlate only when the finding location exactly matches an already-linked sink line.

The interpretation labels do not change:

- route/call relationships remain `structural-route-call-evidence-only`;
- request source/call/sink relationships remain `structural-request-source-call-sink-evidence-only`;
- aggregate repository route analysis remains `repository-structural-route-flow-evidence-only`.

None of those labels imply runtime reachability, exploitability, effective authentication/authorization, or absence of vulnerabilities.

## Resource and trust boundaries

Django resolution does not import or execute repository Python code and performs no network access. Source reads are restricted to the already-supplied repository file inventory, reject path escape and symlinks, and retain the repository analysis source-size bounds. Repository text, import statements, route metadata, and downstream scanner findings remain untrusted input.
