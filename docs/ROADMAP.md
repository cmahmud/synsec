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
- [ ] Function/call graph
- [ ] Routes and externally reachable entry points
- [ ] Authentication/authorization context
- [ ] Database, filesystem, process, and network sinks
- [ ] Dependency reachability beyond scanner-provided call analysis
- [ ] Test ownership and coverage context around findings

## Phase 3 — Contextual security review

- [x] Provider-agnostic OpenAI-compatible AI review adapter
- [x] Explicit opt-in for model review
- [x] Separate deterministic scanner evidence from model inference
- [x] Seven-question evidence gate for model review
- [x] Source-code context disabled by default and separately opt-in
- [ ] Multi-model reviewer/verifier consensus
- [ ] Repository-aware explanation of reachability and impact
- [ ] Suggested patch generation
- [ ] Suggested regression/security tests
- [x] Safe rescan-after-remediation verification primitive
- [x] Finding lifecycle: new, confirmed, false positive, accepted risk, fixed, regressed

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

- [ ] GitHub App
- [ ] Repository installation flow
- [ ] Pull-request scanning
- [ ] Commit status / checks
- [ ] Inline SARIF/code-scanning findings
- [ ] Scheduled repository scans
- [ ] Optional remediation pull requests with explicit approval
- [ ] GitLab and Bitbucket adapters

## Phase 6 — Persistent web application

- [ ] Project/repository dashboard
- [ ] Scan history
- [ ] Security-score history
- [ ] New/fixed/regressed views
- [ ] Finding detail page with source evidence
- [ ] Dependency and SBOM views
- [ ] Repository posture view
- [ ] Team triage workflow
- [ ] Finding comments/ownership

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
