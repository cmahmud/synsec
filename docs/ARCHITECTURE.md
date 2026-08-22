# SynSec Architecture

## Goal

SynSec should act as the orchestration and intelligence layer around mature security scanners rather than reimplementing every detection engine.

The core pipeline is:

```text
repository
   |
   v
scanner adapters
   |
   v
raw scanner results
   |
   v
normalization
   |
   v
correlation / deduplication
   |
   v
repository context and reachability
   |
   v
triage / remediation
   |
   +-- CLI
   +-- web dashboard
   +-- CI checks
   +-- pull-request remediation
```

## Packages

### `@synsec/core`

Owns scanner-independent domain types and correlation logic. Scanner-specific response shapes should never leak into the rest of the application.

### `@synsec/scanner-sdk`

Defines the adapter contract used by all scanner integrations and provides shared process-execution primitives.

Scanner adapters are expected to:

1. report whether the underlying engine is available;
2. execute it without invoking a shell;
3. parse its native output;
4. emit the normalized SynSec finding schema.

### `@synsec/scanners`

Contains built-in integrations. The first integration is Trivy.

Planned adapters include Opengrep, Gitleaks, OSV-Scanner, Syft, Grype, Checkov, and OpenSSF Scorecard.

### `@synsec/cli`

Provides the local developer workflow. The initial commands are `doctor` and `scan`.

## Finding model

Each normalized finding preserves:

- category;
- severity;
- confidence;
- scanner and rule ID;
- code/file location;
- CVE/CWE/OSV/GHSA identifiers where available;
- evidence;
- remediation guidance;
- scanner-specific metadata.

The model is intentionally scanner-independent so multiple engines can contribute evidence to one logical vulnerability.

## Correlation

The first correlation implementation uses a deterministic fingerprint derived from the finding category, rule/identifier context, location, and title. This is only the bootstrap implementation.

Later versions should use progressively stronger correlation:

1. exact fingerprints;
2. shared CVE/CWE/OSV/GHSA identifiers;
3. overlapping code locations;
4. equivalent source/sink data-flow paths;
5. semantic similarity;
6. repository graph context.

The result presented to the user should be one logical finding with multiple supporting scanner sources, not several duplicate alerts.

## AI review layer

The model layer should receive selected repository context rather than an entire repository by default.

Context retrieval should eventually include:

- imports and module relationships;
- route and controller ownership;
- authentication and authorization middleware;
- source-to-sink call paths;
- database access;
- configuration and deployment files;
- tests covering the affected code;
- version-control history relevant to the finding.

AI-generated conclusions must remain distinguishable from deterministic scanner evidence. Findings should preserve scanner evidence even when the AI layer changes severity, confidence, exploitability assessment, or remediation guidance.

## Execution model

Local development starts with scanner binaries installed on the host. Containerized workers can be added later for isolation and reproducibility.

Long term, scan workers should be disposable and should receive the minimum credentials necessary to clone or inspect the requested repository.

## Security boundaries

SynSec is repository-first and defensive by default. External attack-surface scanning or bug-bounty workflows are secondary modes and require explicit authorization boundaries.

Repositories under analysis must be treated as untrusted input. Scanner workers should eventually use sandboxing because repositories can contain malicious build scripts, symlinks, archives, and configuration designed to affect analysis tooling.
