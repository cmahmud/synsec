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
- [x] OpenSSF Scorecard adapter
- [x] Bounded parallel scanner orchestration
- [x] Scanner failure isolation
- [x] Versioned JSON report format
- [x] SARIF 2.1 export
- [x] Self-contained HTML report/dashboard
- [x] Stronger cross-scanner advisory and source-location correlation
- [x] Configurable CI severity threshold
- [x] Baseline support with new/fixed/persisting findings
- [x] Secret redaction in normalized output
- [ ] Syft SBOM adapter
- [ ] Generic SARIF import
- [ ] Changed-files-only scan mode

## Phase 2 — Repository intelligence

- [x] Language/framework inventory
- [x] Safe bounded finding-to-code context retrieval
- [ ] Persistent repository index
- [ ] Import/module graph
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
- [ ] Safe rescan-after-remediation workflow
- [ ] Finding lifecycle: new, confirmed, false positive, accepted risk, fixed, regressed

## Phase 4 — Reusable workflows / skills

The orchestration layer should be able to expose small reusable defensive workflows rather than hard-coding one giant agent prompt.

- [ ] Repository review workflow
- [ ] Dependency review workflow
- [ ] Secrets review workflow
- [ ] IaC review workflow
- [ ] Fix verification workflow
- [ ] Report-writing workflow
- [ ] Provider/model routing policy by task and cost
- [ ] User-defined workflow/skill format with explicit capabilities
- [ ] Human approval boundaries for any action that changes a repository

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
