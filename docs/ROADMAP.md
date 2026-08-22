# SynSec Roadmap

This roadmap separates what is already usable in the repository from the deeper analysis and hosted-product work that follows it.

## Phase 0 — Foundation

- [x] Standalone public repository
- [x] Normalized finding model
- [x] Scanner adapter SDK
- [x] CLI foundation
- [x] Initial Trivy integration
- [x] Deterministic correlation layer
- [x] CI on Node 20 and Node 24
- [x] Versioned configuration format

## Phase 1 — Repository scanner MVP (v0.2)

- [x] Opengrep adapter
- [x] Betterleaks adapter
- [x] Gitleaks fallback adapter
- [x] OSV-Scanner adapter
- [x] Trivy adapter
- [x] Grype adapter
- [x] Checkov adapter
- [x] Syft SBOM adapter and normalized scanner-artifact model
- [x] OpenSSF Scorecard adapter
- [x] Bounded parallel scanner orchestration
- [x] Scanner failure isolation
- [x] Refuse false clean reports when no selected scanner can run
- [x] Versioned JSON report format
- [x] SARIF 2.1 export
- [x] Generic SARIF 2.1 import into normalized findings
- [x] Self-contained HTML report/dashboard
- [x] Stronger cross-scanner advisory and source-location correlation
- [x] Configurable CI severity threshold
- [x] Baseline support with new/fixed/persisting findings
- [x] Secret redaction in normalized output
- [x] Changed-file finding scope with persisted base/file metadata
- [x] Direct changed-file execution for Opengrep and Betterleaks
- [ ] Native incremental execution for every scanner that can safely support it

## Phase 2 — Repository intelligence

- [x] Language/framework inventory
- [x] Safe bounded finding-to-code context retrieval
- [x] Persistent repository index
- [x] Import/module graph with bounded dependency/dependent traversal
- [x] Bounded same-file lexical call-graph primitive for JavaScript/TypeScript and Python
- [x] Conservative decorator-route to callable-entrypoint mapping
- [x] Bounded route-level lexical authentication/authorization context
- [x] Bounded route-level lexical process/filesystem/database/network sink context
- [x] Bounded repository posture summary from route/auth/sink signals
- [ ] Full function/call graph with reliable cross-module symbol resolution
- [ ] Broad routes and externally reachable entry points across supported frameworks
- [ ] Framework-aware authentication/authorization enforcement semantics
- [ ] Data-flow-aware sink reachability beyond lexical proximity
- [ ] Dependency reachability beyond scanner-provided call analysis
- [ ] Test ownership and coverage context around findings

The current call graph is deliberately labeled lexical evidence rather than runtime reachability. It resolves unambiguous direct same-file calls and leaves qualified, external, or ambiguous calls unresolved. Decorator-based route mapping only links a route when one function declaration is structurally close enough to be unambiguous; generic router registrations remain unresolved rather than guessing a handler.

Route authentication and sink context are similarly conservative. They record bounded same-file security signals near indexed routes and label the results `lexical-auth-signals-only` or `lexical-sink-signals-only`. Absence of nearby auth is reported only as `no-auth-signal-observed`, and nearby sinks are not treated as proven data-flow or call reachability. The repository posture summary aggregates these bounded signals for prioritization while explicitly remaining `bounded-lexical-posture-only`.

## Phase 3 — Contextual security review

- [x] Provider-agnostic OpenAI-compatible AI review adapter
- [x] Explicit opt-in for model review
- [x] Separate deterministic scanner evidence from model inference
- [x] Seven-question evidence gate for model review
- [x] Source-code context disabled by default and separately opt-in
- [x] Deterministic multi-review consensus aggregation with disagreement/insufficient-review handling
- [ ] Multi-model reviewer execution/orchestration
- [ ] Repository-aware explanation of reachability and impact
- [ ] Suggested patch generation
- [ ] Suggested regression/security tests
- [x] Safe rescan-after-remediation verification primitive
- [x] Finding lifecycle: new, confirmed, false positive, accepted risk, fixed, regressed

Consensus remains model inference, not scanner evidence. Duplicate model identities do not count as independent reviewers, split verdicts fail closed to `uncertain`, insufficient reviewer sets do not fabricate consensus, and gate answers are aggregated with disagreement preserved.

## Phase 4 — Reusable workflows / skills

The orchestration layer should expose small reusable defensive workflows rather than hard-coding one giant agent prompt.

- [x] Repository review workflow
- [x] Dependency review workflow
- [x] Secrets review workflow with source-context prohibition
- [x] Infrastructure/IaC review workflow
- [x] Fix verification workflow
- [x] Report-writing workflow
- [x] Provider/model routing policy by task and cost
- [x] User-defined workflow/skill format with explicit capabilities
- [x] Explicit capability declarations per built-in workflow
- [x] Human approval boundary declared for any repository-changing action
- [x] External network assessment forbidden in repository workflows

These workflows operate on repository evidence and scanner results. They are not a mechanism for silently expanding into external targets.

## Phase 5 — Git hosting and CI

- [x] GitHub Actions context/event parsing primitives
- [x] Deterministic GitHub check-result and inline-annotation generation
- [x] Baseline-aware PR annotation filtering and severity-threshold conclusions
- [x] Narrow fixed-host Checks API publication primitive
- [x] Completed-report → GitHub check publication orchestration
- [x] GitHub Actions repository scan → check runner with PR changed-file defaults
- [x] Report/commit binding before check publication
- [ ] GitHub App
- [ ] Repository installation flow
- [ ] Packaged Actions entrypoint / workflow template
- [ ] Baseline acquisition for pull-request scans
- [ ] Inline SARIF/code-scanning upload
- [ ] Scheduled repository scans
- [ ] Optional remediation pull requests with explicit approval
- [ ] GitLab and Bitbucket adapters

The Actions runner consumes the existing repository scan engine rather than introducing a second scanner path. Pull-request contexts default to changed-file scanning against `origin/<base>`, push contexts default to full repository scans, and publication is refused when the scan cannot identify its commit or the report commit differs from the GitHub head being annotated.

See [GITHUB.md](./GITHUB.md) for the current integration contract and security boundaries.

## Phase 6 — Persistent web application

- [x] Deterministic report-history aggregation for score, finding count, churn, and finding lifetime
- [x] Bounded local scan-history store with atomic writes and trend-safe snapshots
- [x] Self-contained trend-safe security-history HTML dashboard renderer
- [x] History-store → restrictive local dashboard file generation
- [ ] Project/repository dashboard application
- [ ] Multi-project/server persistence layer
- [ ] Interactive security-score history UI
- [ ] New/fixed/regressed views
- [ ] Finding detail page with source evidence
- [ ] Dependency and SBOM views
- [ ] Interactive repository posture view
- [ ] Team triage workflow
- [ ] Finding comments/ownership

The local history store retains only report identifiers, timestamps, commit/branch metadata, aggregate counts/scores, and finding fingerprint/title/severity tuples. It deliberately omits source excerpts, scanner diagnostics, repository URLs, artifacts, and secret-bearing evidence. Retention is bounded, writes are atomic, and invalid/corrupt stores fail closed. The self-contained history dashboard renders only this trend-safe model, escapes titles/content, and can be written with restrictive local permissions. A multi-project database and interactive web application remain future work.

## Phase 7 — Isolated scan workers

- [ ] Containerized scanner images
- [ ] Job queue
- [ ] Per-scan workspace isolation
- [ ] Resource limits and timeouts
- [ ] Network policy
- [ ] Horizontal workers
- [ ] Artifact retention policy
- [ ] Secrets/credential minimization for private repository clones

## Later — explicitly authorized external assessment

External attack-surface or bug-bounty workflows may be explored as a separate mode only after scope/authorization controls exist. They should not define the core architecture, should never silently expand target scope, and should not weaken the repository-first defensive defaults.
