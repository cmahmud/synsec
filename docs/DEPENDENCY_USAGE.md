# Dependency usage evidence

SynSec can attach repository import context to dependency, container, and supply-chain findings. This context is intended to help triage vulnerable packages; it is not a claim that a package executes in production or that a vulnerable code path is reachable.

## Resolver-aware evidence

The scan engine builds the repository module graph once and uses it for both conservative incremental planning and dependency usage enrichment. `findExternalDependencyUsage()` compares raw import records with that graph before labeling a package `observed-import`.

Imports that SynSec has uniquely resolved to repository files are excluded from third-party dependency evidence. This matters especially in Python, where an absolute import can name either a local package or an installed distribution. For example, when the repository contains an explicit `service/__init__.py` and `from service.db import load` uniquely resolves to `service/db.py`, a dependency finding whose package is named `service` does not receive an `observed-import` signal from that local edge.

Resolution fails closed. If local module identity is ambiguous, SynSec does not guess that the import is local; the unresolved import remains eligible third-party evidence. A simultaneous `service/db.py` and `service/db/__init__.py`, for example, is not used to suppress dependency usage evidence.

## Report shape

Resolver-aware usage contains the existing package name, status, and bounded import evidence plus:

- `excludedRepositoryLocalImportCount`: how many matching imports were removed because they uniquely resolved to repository files;
- `interpretation: observed-import-evidence-not-runtime-reachability`.

Evidence is capped at 100 records even when a caller requests a larger limit. The normal engine path uses the smaller default bound.

## Security meaning

`observed-import` means only that SynSec observed unresolved/external import syntax matching the dependency name. It does not establish that:

- the imported module executes on a real request or job;
- the vulnerable function or version-specific code path is used;
- attacker-controlled data can reach the package;
- a route is deployed or externally accessible;
- the scanner finding is exploitable.

Those questions require stronger call/data-flow, framework, runtime, or scanner-native reachability evidence. SynSec keeps the import signal separate so triage can benefit from repository context without promoting syntax into a vulnerability proof.

## Defensive scope

Dependency usage analysis reads repository index data only. It does not import project modules, execute package code, contact package services, probe live targets, or expand the selected repository scope.
