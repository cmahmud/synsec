# Incremental repository scan contract

SynSec may reduce repository scan work only when it can preserve a defensible repository-first scope. Incremental execution is an optimization, not a claim that unselected files are safe or unreachable.

## Local and GitHub Actions scans

`runScanEngine()` can derive changed files from a local Git base or accept a caller-supplied changed-file set. Caller-supplied paths are accepted only when `changedOnly=true` and an explicit `changedBase` provenance identifier is present. Paths must be bounded, repository-relative, free of traversal/control characters, and are normalized/deduplicated before scanner execution.

The engine then builds the existing repository index and resolved local module graph before choosing a scope. `buildIncrementalScanPlan()` always includes direct changes and may add bounded local dependents. It falls back to a full repository scan for high-impact repository/configuration files, unsafe paths, excessive change sets, changed analyzable source missing from the graph, or dependent expansion that would exceed its bound. A no-op targeted request also becomes a full scan rather than relying on adapter-specific empty-scope behavior.

The planner interpretation is deliberately `coverage-heuristic-not-proof-of-unaffected-code`. Resolved import relationships are structural evidence only; they do not prove runtime reachability.

## Native adapter narrowing

Adapters may use the planner's final changed-file list to reduce scanner work only when the underlying scanner exposes a file-scoped mode that preserves repository-local target boundaries.

Opengrep and Betterleaks already narrow execution directly to changed files. Checkov now uses its supported repeated `-f/--file` mode for a bounded changed-file scope, runs from the authorized repository working directory, deduplicates paths, and independently rejects absolute or traversal-shaped file names. If no changed-file scope is supplied, Checkov retains its normal directory scan.

Checkov's adapter-level changed-file list is capped at 500 entries even though the engine normally applies a tighter planner bound. The adapter check is defense in depth for direct SDK use. It does not silently truncate an oversized request; it fails instead.

Other scanner adapters may still perform their normal repository analysis before SynSec filters file-located findings. A scanner is not described as natively incremental until its adapter explicitly narrows the underlying scanner command safely.

## Hosted GitHub App pull requests

Hosted App workers already acquire the exact queued base and head commits into separate detached workspaces. `deriveExactChangedFiles()` compares those two local Git trees using bounded `git ls-tree` output. It does not trust branch names, webhook clone URLs, default branches, scanner-suggested targets, or an unbounded history fetch.

Only changed blob paths that exist in the head can become targeted scanner input. The comparison falls back to a full repository scan when:

- either tree cannot be read within the configured time/output bounds;
- tree output is malformed or contains unsafe paths;
- repository/tree entry counts or changed-file counts exceed bounds;
- a changed entry is not a normal blob (for example a submodule entry); or
- any path was deleted.

Deletions intentionally force a full scan because targeted scanner adapters must not receive absent paths and SynSec does not manufacture a partial deletion-remediation proof.

When the exact tree comparison succeeds, the resulting direct paths still pass through the engine's conservative incremental planner before scanner execution. Therefore high-impact or structurally ambiguous changes can still expand to a full repository scan.

## Baseline and remediation semantics

An incremental report cannot treat every baseline finding missing from the partial result as fixed. `applyEvidenceAwareBaseline()` marks an absent baseline finding fixed only when the current report covered that finding path and at least one scanner that previously detected it ran again. Findings outside a changed-file scope, findings without a path in a partial scan, and findings whose detecting scanner did not rerun are not reported as fixed merely because they are absent.

New and persisting findings continue to use the stable normalized SynSec fingerprint. The same evidence rule protects full scans from calling a finding fixed when its detecting scanner was omitted from the current scanner set.

## SARIF safety

Hosted App workers currently keep SARIF-enabled pull-request jobs on full-repository head scans even when an exact changed-file plan is available. Publishing a partial SARIF analysis as the latest code-scanning analysis can make untouched alerts appear absent, so SynSec does not use partial hosted SARIF until it has an explicit merge-safe publication contract.

Checks publication can use the changed-file report because annotations are report-local and baseline-aware. Publication still requires the completed report commit to equal the queued GitHub head SHA.

## Security boundary

Incremental planning never authorizes network assessment or target expansion. The only targets are files inside the already-authorized repository checkout. Scanner subprocess credential minimization, fixed-host GitHub acquisition/publication, installation authorization checks, exact commit binding, and existing workflow capability restrictions remain unchanged.
