# SynSec Architecture

## Goal

SynSec is the orchestration, normalization, correlation, reporting, and contextual-review layer around mature security engines. Detection engines remain replaceable external tools rather than being copied into the application.

The v0.2 pipeline is:

```text
repository
   |
   +----> safe inventory --------------------------+
   |                                              |
   v                                              |
scanner availability                              |
   |                                              |
   v                                              |
bounded concurrent scanner runner                 |
   |                                              |
   +-- Opengrep                                   |
   +-- Betterleaks / Gitleaks                     |
   +-- OSV-Scanner                                |
   +-- Trivy                                      |
   +-- Grype                                      |
   +-- Checkov                                    |
   |                                              |
   v                                              |
normalized findings <-----------------------------+
   |
   v
correlation / deduplication
   |
   +--------------------+
   |                    |
   v                    v
versioned report    optional AI review
JSON/HTML/SARIF     separate output/evidence
   |
   v
baseline comparison
new / fixed / persisting
```

## Package boundaries

### `@synsec/core`

Owns scanner-independent domain types and deterministic correlation.

Scanner-native fingerprints are retained as source metadata on individual findings, while the correlation layer computes its own fingerprint so two different engines can corroborate the same issue.

Current stronger deterministic signals include:

- shared vulnerability advisory IDs plus package identity for dependency findings;
- same file and line for redacted secret findings;
- same file, line, and CWE for SAST findings;
- conservative scanner-aware fallbacks when there is not enough evidence to merge alerts safely.

### `@synsec/config`

Owns the stable `synsec.config.json` schema. It controls scanner selection, concurrency, timeouts, CI failure thresholds, report locations, baselines, and AI privacy behavior.

### `@synsec/scanner-sdk`

Defines the adapter contract and the shared process runner.

Important process properties:

- `spawn` is used without a shell;
- arguments are passed as an array rather than interpolated into command text;
- timeouts and abort signals are supported;
- scanner stdout/stderr remain separate.

### `@synsec/scanners`

Contains built-in adapters for external engines.

An adapter must:

1. report binary availability;
2. invoke only its intended scanner binary;
3. request machine-readable output;
4. normalize the result into `Finding` objects;
5. avoid retaining secrets where the engine can redact them;
6. treat documented scanner "findings found" exit codes separately from execution failures.

The current engines are Opengrep, Betterleaks, Gitleaks, OSV-Scanner, Trivy, Grype, and Checkov.

### `@synsec/repository`

Provides bounded repository intelligence without executing the project under analysis.

The v0.2 implementation:

- walks files while excluding common generated/vendor directories;
- skips symlinks;
- caps inventory and per-file analysis size;
- detects languages and common frameworks;
- builds a structural local module graph for supported JavaScript/TypeScript/Python imports;
- builds bounded lexical call-graph, route, authentication, sink, test-ownership, and coverage context;
- expands incremental scan scope through bounded known local dependents;
- retrieves bounded text around a finding only after verifying that the path remains inside the repository root;
- refuses large/binary context files.

Module resolution deliberately fails closed when identity is ambiguous. JavaScript/TypeScript local edges require relative specifiers. Python relative imports are resolved when a unique repository module/package exists. Absolute Python imports such as `service.db` are treated as repository-local only when the indexed repository contains an explicit top-level `service/__init__.py` package and exactly one matching module/package target. A standalone `requests.py` therefore does not cause `import requests` to be guessed as local, and a simultaneous `service/db.py` plus `service/db/__init__.py` remains unresolved.

This module graph is structural import evidence, not function-level data flow or production reachability. Its immediate execution consequence is conservative incremental coverage: changing a uniquely resolved local Python dependency can include bounded importing modules, while unresolved imports do not manufacture dependent scope.

### `@synsec/report`

Owns the versioned SynSec report model and presentation formats:

- JSON (`schemaVersion: 1.0`);
- SARIF 2.1.0;
- self-contained HTML;
- baseline comparison.

The HTML renderer escapes finding-controlled content before insertion.

### `@synsec/engine`

Coordinates a scan.

Responsibilities include:

- Git repository metadata discovery;
- credential stripping from remote URLs;
- scanner availability checks;
- bounded concurrency;
- failure isolation;
- repository inventory and structural context;
- conservative dependency-aware incremental planning;
- report construction;
- CI severity threshold evaluation.

The engine refuses to generate a reassuring "clean" report if no selected scanner was able to run. If every available scanner fails, the scan itself fails.

### `@synsec/ai`

Provides the optional contextual review boundary.

The first implementation deliberately uses an OpenAI-compatible protocol rather than importing a model-vendor SDK. A local or remote model router can therefore sit behind the same interface.

AI review is not part of deterministic detection. It writes a separate review artifact and is governed by a seven-question evidence gate. Source excerpts are disabled by default and only retrieved/sent when explicitly enabled.

### `@synsec/cli`

Provides local product workflows:

- `init`
- `doctor`
- `scan`
- `review`
- `render`
- `baseline`

The CLI is intentionally useful without a hosted backend.

## Finding model

A normalized finding can preserve:

- category;
- severity;
- confidence;
- scanner and rule ID;
- source location;
- CVE/CWE/OSV/GHSA identifiers;
- scanner evidence when safe;
- remediation guidance;
- scanner-specific metadata;
- native scanner fingerprint.

A correlated finding adds a SynSec fingerprint, a selected primary representation, duplicate/corroborating results, and the contributing scanner sources.

## Failure semantics

Security tooling must not confuse missing coverage with a clean bill of health.

SynSec therefore distinguishes:

- scanner not selected;
- scanner selected but binary unavailable;
- scanner ran successfully with zero findings;
- scanner ran successfully with findings;
- scanner execution failed.

At least one selected scanner must complete successfully for a report to be created.

## AI/privacy boundary

AI is disabled by default.

When enabled without source context, the provider receives normalized finding metadata only. Enabling `sendSourceContext` or `--ai-source` permits a small bounded excerpt around the affected line. Whole repositories are not sent by default.

AI conclusions never overwrite or delete deterministic scanner evidence. This is important for auditing false positives, model disagreements, and future reviewer/verifier consensus.

## Reusable workflow direction

The model-facing layer should evolve into small reusable defensive workflows instead of one giant prompt. Examples include dependency review, secrets review, IaC review, remediation review, and report drafting.

A workflow should declare the evidence it may read and the actions it may request. Repository-changing actions should require an explicit approval boundary. External network-assessment workflows belong to a separate authorized mode rather than inheriting repository permissions implicitly.

## Current execution trust model

Repositories under analysis are untrusted input. v0.2 avoids directly executing their application/build scripts, skips symlinks in repository inventory, and invokes scanner binaries without a shell. Scanner subprocesses also use a credential-minimized environment and constrained command lookup as defense in depth.

External scanners still have their own parsers, archive handlers, network behavior, and implementation risks. Hosted production operation therefore requires externally enforced disposable container/sandbox controls rather than treating the Node child-process boundary as isolation. SynSec's production isolation profile can fail closed on a reviewed declaration of those controls, but it does not itself create or certify the sandbox.

## Repository graph direction

The current structural graph already includes bounded local module relationships, same-file lexical calls, conservative route/handler mapping, authentication and sensitive-sink signals, test ownership, and coverage context. The next intelligence steps should deepen these signals without overstating them, including:

- framework-aware cross-module handler resolution where imports/exports are unambiguous;
- bounded cross-module call relationships;
- source-to-sink/data-flow analysis with explicit uncertainty handling;
- dependency reachability beyond observed imports;
- richer framework middleware/controller composition;
- stronger linkage to relevant tests and version-control context.

These graph layers should improve triage and fix suggestions without requiring the model to ingest an entire repository for each finding and without authorizing live-target probing.
