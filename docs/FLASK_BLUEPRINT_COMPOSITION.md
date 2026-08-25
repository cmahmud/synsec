# Flask Blueprint composition

SynSec performs a bounded structural analysis of explicit Flask `Blueprint` registration so repository findings can be correlated with composed route identities without executing application code.

## Accepted shape

The analyzer accepts only narrow, auditable forms:

- one-line, unaliased `from flask import Flask, Blueprint` imports;
- exact `app = Flask(__name__)` application roots;
- exact `name = Blueprint("literal", __name__)` declarations, optionally with one literal `url_prefix`;
- exact `receiver.register_blueprint(name)` calls, optionally with one literal `url_prefix`;
- repository-local named Python imports that resolve uniquely to one matching Blueprint declaration and remain unshadowed before registration;
- named Blueprint route decorators such as `@users.get("/42")` and `@users.route("/42")` followed by one uniquely nearest Python function.

Nested Blueprint registration is followed only up to configured depth and output limits. The repository root, file type, regular-file status, symlink status, and source-size bound are revalidated before source analysis.

## Fail-closed cases

SynSec produces no composed evidence for dynamic prefixes, Blueprint factories, dotted Blueprint references, imported Flask application roots, wildcard or parenthesized imports, ambiguous declarations, shadowed imports, use-before-definition, unresolved repository modules, cycles, or routes whose handler cannot be resolved uniquely inside the declaration bound.

A `.route(...)` decorator is reported with method `ANY`; SynSec does not infer `methods=` semantics from arbitrary decorator arguments. Framework runtime behavior is not executed or simulated.

## Security interpretation

Composed entries carry:

`structural-flask-blueprint-composition-not-runtime-reachability`

This means the evidence supports a repository-level statement such as: a literal registration chain structurally connects a Flask app root to this Blueprint route and its bounded static call/sink evidence.

It does **not** prove that:

- Flask imports or registers the Blueprint in a deployed process;
- the route is externally reachable;
- a reverse proxy exposes the route;
- authentication or authorization is effective;
- request data reaches a sink at runtime;
- a finding is exploitable or non-exploitable.

Dynamic or ambiguous application behavior remains unresolved rather than being converted into a security claim.
