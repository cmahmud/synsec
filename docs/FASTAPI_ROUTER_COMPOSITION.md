# FastAPI router composition

SynSec can compose a deliberately narrow subset of FastAPI `APIRouter` prefix wiring so repository findings can retain a more exact structural route identity across repository-local router modules.

## Supported evidence

The analyzer accepts only explicit one-line forms that can be checked without importing or executing repository code:

```python
from fastapi import APIRouter
router = APIRouter(prefix="/users")

@router.get("/{user_id}")
def get_user(user_id):
    ...
```

and a repository-local include such as:

```python
from .users import router as users_router
app.include_router(users_router, prefix="/api")
```

For that shape SynSec may attach `/api/users/{user_id}` to the already-resolved handler and its existing bounded call/sink evidence. Nested `router.include_router(...)` relationships are also followed within configured depth and output limits.

Imported routers must use one explicit named Python import that resolves through SynSec's repository module graph to exactly one supplied file containing one matching `APIRouter` declaration. Imported bindings must remain unshadowed at the include site. Same-file routers must be declared before they are used.

## Fail-closed cases

SynSec does not compose a route when it encounters unsupported or ambiguous wiring, including:

- dynamic or computed prefixes;
- router factories or other call expressions used as the included router;
- dotted/member router references;
- aliased or shadowed `APIRouter` constructors;
- wildcard or parenthesized imports;
- duplicate matching router declarations;
- repository imports that do not resolve uniquely;
- a same-file router used before its declaration;
- traversal beyond configured include depth or output bounds;
- repeated router nodes in a nested include path.

Unsupported wiring stays unresolved instead of being guessed.

## Security interpretation

Composed routes carry the label:

`structural-fastapi-router-composition-not-runtime-reachability`

This means SynSec observed a bounded static source relationship. It does **not** prove that Python imports succeed, that FastAPI executes an `include_router()` call, that a specific application object is deployed, that the route is reachable, that dependencies or middleware run, or that any request is attacker-controlled or exploitable.

The composition layer reuses existing handler, call, request-input, and sink evidence. Those layers keep their own structural-only interpretation and bounds; a composed prefix does not upgrade any of them into runtime proof.

## Resource bounds

`buildRepositoryRouteFlowAnalysis()` exposes `maxFastApiIncludeDepth` and `maxFastApiComposedRoutes`. The router analyzer also inherits the aggregate repository analysis file-safety checks: path escapes, symlinks, missing/non-regular files, oversized source files, and files outside the supplied inventory are not analyzed.
