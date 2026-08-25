# FastAPI route dependency evidence

SynSec performs a deliberately narrow structural analysis of explicit FastAPI route-level dependencies. The goal is to improve repository review context without converting framework syntax or authentication-looking names into claims about runtime security.

## Supported evidence

For a Python route decorator already recognized by the repository index, SynSec can inspect literal route-level dependency lists such as:

```python
from fastapi import Depends
from .auth import require_user

@router.get("/account", dependencies=[Depends(require_user)])
def account():
    ...
```

The dependency wrapper must be an unaliased `Depends` or `Security` name explicitly imported from `fastapi` before the route. Each dependency expression must be exactly `Depends(name)` or `Security(name)` with a simple Python identifier.

A dependency identifier resolves only when SynSec finds exactly one of these targets:

- one unique same-file Python function that is already defined before the route decorator; or
- one unshadowed explicit repository-local `from module import name [as alias]` binding whose module graph resolves to one repository file containing one matching function.

For a resolved dependency, SynSec may collect existing lexical authentication, authorization, session, or token signals from that function and its bounded same-file call neighborhood. This evidence is labeled `structural-fastapi-dependency-evidence-not-runtime-protection`.

## Fail-closed cases

SynSec deliberately does not resolve:

- dependency factories such as `Depends(build_guard())`;
- dotted or member expressions such as `Depends(auth.require_user)`;
- dynamically constructed dependency lists;
- lambda or nested expressions;
- wildcard or parenthesized repository imports;
- ambiguous same-name functions or module targets;
- imported dependency names that are reassigned, redeclared, rebound by another import, or otherwise shadowed before the route;
- `Depends` or `Security` wrappers that are aliased or shadowed locally.

Unsupported or ambiguous dependency syntax contributes no positive runtime-security conclusion.

## Security semantics

This analysis is structural repository evidence only. It does **not** prove that:

- the route is registered or reachable at runtime;
- FastAPI executes the dependency for a particular deployment;
- a dependency successfully authenticates or authorizes a request;
- a security token is valid;
- a request cannot bypass another runtime path;
- the route, dependency, or downstream call is exploitable or non-exploitable.

Authentication-looking function names are not evidence by themselves. SynSec reports auth-related context only when an existing lexical auth signal appears inside the resolved bounded dependency call scope.

This layer intentionally complements, rather than replaces, runtime tests, framework configuration review, deployment verification, and application-specific authorization analysis.
