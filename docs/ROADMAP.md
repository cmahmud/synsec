# SynSec Roadmap

## Phase 0 — Foundation

- [x] Standalone public repository
- [x] Normalized finding model
- [x] Scanner adapter SDK
- [x] CLI skeleton
- [x] First real scanner integration: Trivy
- [x] Initial correlation layer
- [ ] CI green on Node 24
- [ ] Stable configuration file format

## Phase 1 — Repository scanner MVP

- [ ] Opengrep adapter
- [ ] Gitleaks adapter
- [ ] OSV-Scanner adapter
- [ ] Checkov adapter
- [ ] Syft + Grype adapters
- [ ] OpenSSF Scorecard adapter
- [ ] SARIF import/export
- [ ] JSON report format with schema versioning
- [ ] Better cross-scanner deduplication
- [ ] Severity and confidence policy engine
- [ ] Ignore/baseline support
- [ ] Scan only changed files when appropriate

## Phase 2 — Repository intelligence

- [ ] Language/framework detection
- [ ] Repository index
- [ ] Import/call graph
- [ ] Routes and externally reachable entry points
- [ ] Authentication/authorization context
- [ ] Database and filesystem sinks
- [ ] Dependency reachability
- [ ] Finding-to-code context retrieval

## Phase 3 — Contextual security review

- [ ] AI-assisted finding triage
- [ ] Explain why a finding matters in this repository
- [ ] Distinguish deterministic evidence from model inference
- [ ] Suggested code patch
- [ ] Suggested tests
- [ ] Rescan after remediation
- [ ] Finding states: new, confirmed, false positive, accepted risk, fixed, regressed

## Phase 4 — Git hosting and CI

- [ ] GitHub App
- [ ] Repository installation flow
- [ ] Pull-request scanning
- [ ] Commit status / checks
- [ ] Inline findings
- [ ] Scheduled scans
- [ ] Optional remediation pull requests
- [ ] GitLab and Bitbucket adapters

## Phase 5 — Web application

- [ ] Project/repository dashboard
- [ ] Scan history
- [ ] Security score
- [ ] New/fixed/regressed findings
- [ ] Finding detail page with source evidence
- [ ] Dependency and SBOM views
- [ ] Repository posture view
- [ ] Team triage workflow

## Phase 6 — Isolated scan workers

- [ ] Containerized scanner images
- [ ] Job queue
- [ ] Per-scan workspace isolation
- [ ] Resource limits and timeouts
- [ ] Network policy
- [ ] Horizontal workers
- [ ] Artifact retention policy

## Later

Authorized attack-surface and bug-bounty workflows can be added later as a separate product mode. They should not define the core architecture or weaken the repository-first authorization model.
