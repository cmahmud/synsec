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
- [x] Bounded likely test-ownership context from resolved imports and filename conventions
- [ ] Full function/call graph with reliable cross-module symbol resolution
- [ ] Broad routes and externally reachable entry points across supported frameworks
- [ ] Framework-aware authentication/authorization enforcement semantics
- [ ] Data-flow-aware sink reachability beyond lexical proximity
- [ ] Dependency reachability beyond scanner-provided call analysis
- [ ] Runtime/test-run coverage context around findings

The current call graph is deliberately labeled lexical evidence rather than runtime reachability. It resolves unambiguous direct same-file calls and leaves qualified, external, or ambiguous calls unresolved. Decorator-based route mapping only links a route when one function declaration is structurally close enough to be unambiguous; generic router registrations remain unresolved rather than guessing a handler.

Route authentication and sink context are similarly conservative. They record bounded same-file security signals near indexed routes and label the results `lexical-auth-signals-only` or `lexical-sink-signals-only`. Absence of nearby auth is reported only as `no-auth-signal-observed`, and nearby sinks are not treated as proven data-flow or call reachability. The repository posture summary aggregates these bounded signals for prioritization while explicitly remaining `bounded-lexical-posture-only`.

Likely test ownership is also structural evidence only. It prioritizes test files that directly import a source module and supplements those with bounded filename-convention matches. It does not claim that a test executes a finding path or that the source is covered at runtime; coverage ingestion remains separate future work.

## Phase 3 — Contextual security review

- [x] Provider-agnostic OpenAI-compatible AI review adapter
- [x] Explicit opt-in for model review
- [x] Separate deterministic scanner evidence from model inference
- [x] Seven-question evidence gate for model review
- [x] Source-code context disabled by default and separately opt-in
- [x] Deterministic multi-review consensus aggregation with disagreement/insufficient-review handling
- [x] Bounded independent multi-reviewer execution API with failure isolation
- [ ] CLI/configured multi-model review UX
- [ ] Repository-aware explanation of reachability and impact
- [ ] Suggested patch generation
- [ ] Suggested regression/security tests
- [x] Safe rescan-after-remediation verification primitive
- [x] Finding lifecycle: new, confirmed, false positive, accepted risk, fixed, regressed

Consensus remains model inference, not scanner evidence. Duplicate model identities do not count as independent reviewers, split verdicts fail closed to `uncertain`, insufficient reviewer sets do not fabricate consensus, reviewer execution is concurrency-bounded, and provider failures are isolated with credential redaction. The package API supports multi-review execution; the CLI still exposes the simpler single-model review path and needs explicit multi-model UX before this becomes the default user-facing workflow.

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
- [x] Packaged Actions entrypoint / workflow template
- [x] Inline SARIF/code-scanning upload
- [x] Provenance-safe pull-request baseline acquisition from the exact local base commit
- [x] Scheduled full-repository workflow template with explicit report-artifact retention
- [x] GitHub App HMAC webhook verification and bounded event normalization
- [x] GitHub App short-lived JWT and fixed-host installation-token exchange primitives
- [x] Explicit GitHub App scan-trigger allowlist for push and selected PR lifecycle events
- [x] Durable webhook delivery replay protection with retry-safe claim release
- [x] Durable local installation authorization state
- [x] Installation/repository-selection event synchronization into authorization state
- [x] Replay-protected authorization-gated local webhook handler
- [x] Bounded framework-free webhook HTTP handler for deployment behind HTTPS
- [x] Installation-scoped exact-commit GitHub repository acquisition primitive
- [x] Exact queued head/base acquisition and hosted PR baseline comparison
- [x] Authorization-aware local scan worker with commit-bound report verification
- [x] Local worker composition through the existing scan engine and Checks/SARIF publishers
- [x] Memory-only App installation-token provider with purpose-specific permission checks
- [x] Single-host local runtime composition with separate durable-state/workspace trees
- [ ] Production TLS/listener deployment, supervision, and operational secret rotation
- [ ] Repository installation/setup UX and richer permission diagnostics
- [ ] Native changed-file execution for hosted PR workers using exact provenance
- [ ] Transactional shared App state/queue for multi-host deployment
- [ ] Optional remediation pull requests with explicit approval
- [ ] GitLab and Bitbucket adapters

The Actions runner consumes the existing repository scan engine rather than introducing a second scanner path. Pull-request contexts default to changed-file scanning against `origin/<base>`, while push, schedule, workflow-dispatch, and other non-PR contexts default to full repository scans. Publication is refused when the scan cannot identify its commit or the report commit differs from the GitHub head being annotated. The packaged Action keeps explicit config/baseline file inputs inside the real checked-out workspace, including symlink resolution, before those files are read.

For PRs without an explicit baseline, the Action can scan the exact event-provided base commit in a temporary detached worktree. The base commit must already be present locally; SynSec does not implicitly fetch a remote or substitute a nearby revision. The resulting report is accepted only when its commit identity matches the requested base SHA, then the temporary worktree is removed.

The Action also writes the completed JSON report under `RUNNER_TEMP` and exposes its path. The scheduled workflow template retains that report only through an explicit caller-owned artifact step with a visible retention period; SynSec does not silently persist security evidence.

GitHub App support now has a coherent single-host local runtime: raw webhook deliveries are bounded and verified, replay-claimed, synchronized into durable authorization state, authorization-gated into a commit-pinned queue, then consumed by workers that recheck authorization and acquire exact repository commits through a fixed GitHub transport. Pull-request jobs acquire and scan both the exact queued base and head; the base report must bind to the queued base SHA before it can become the head baseline, and the head report must bind to the queued head SHA before Checks/SARIF publication. Credentials are created afresh in memory, never handed to scanners, and checked against operation-specific permission requirements. Hosted PR execution is still full-repository at each commit; native changed-file optimization remains future work. See [GITHUB_APP.md](./GITHUB_APP.md).

See [GITHUB.md](./GITHUB.md) for the current Actions integration contract and security boundaries.

## Phase 6 — Persistent web application

- [x] Deterministic report-history aggregation for score, finding count, churn, and finding lifetime
- [x] Bounded local scan-history store with atomic writes and trend-safe snapshots
- [x] Self-contained trend-safe security-history HTML dashboard renderer
- [x] History-store → restrictive local dashboard file generation
- [x] Bounded lifecycle finding-ownership metadata foundation
- [ ] Project/repository dashboard application
- [ ] Multi-project/server persistence layer
- [ ] Interactive security-score history UI
- [ ] New/fixed/regressed views
- [ ] Finding detail page with source evidence
- [ ] Dependency and SBOM views
- [ ] Interactive repository posture view
- [ ] Team triage workflow
- [ ] Finding comments and richer collaboration history

The local history store retains only report identifiers, timestamps, commit/branch metadata, aggregate counts/scores, and finding fingerprint/title/severity tuples. It deliberately omits source excerpts, scanner diagnostics, repository URLs, artifacts, and secret-bearing evidence. Retention is bounded, writes are atomic, and invalid/corrupt stores fail closed. The self-contained history dashboard renders only this trend-safe model, escapes titles/content, and can be written with restrictive local permissions. Lifecycle ownership is separately bounded triage metadata preserved across state transitions/rescans; it is not scanner evidence and does not make the current local store a multi-user collaboration database.

## Phase 7 — Isolated scan workers

- [x] Scanner subprocess timeout, abort, output-memory, and kill-escalation bounds
- [x] Credential-minimized default scanner subprocess environment
- [x] Bounded durable local scan-job queue with leases/retries
- [x] Commit-pinned temporary checkout workspace acquisition and cleanup
- [x] Authorization recheck before worker credential/source acquisition
- [x] Separation of durable App state and repository workspace directory trees
- [ ] Containerized scanner images
- [ ] Per-scan process/container workspace isolation
- [ ] OS/container CPU and memory limits
- [ ] Network policy
- [ ] Horizontal workers
- [ ] Artifact retention policy
- [ ] Filesystem credential minimization for private-repository scan workspaces

External scanners no longer inherit the full parent process environment by default. SynSec passes a small execution/locale/certificate allowlist and requires an explicit environment when a scanner genuinely needs additional variables. Hosted GitHub acquisition uses a separate short-lived transport credential, keeps it out of scanner inputs and Git argv, disables inherited Git configuration, and removes temporary checkout workspaces after handling. The local runtime also refuses to place repository workspaces inside durable App state. This materially narrows credential/source exposure but is not a complete sandbox: scanner processes still need container isolation, OS resource limits, network policy, and stronger filesystem credential separation before a production multi-tenant worker deployment.

## Later — explicitly authorized external assessment

External attack-surface or bug-bounty workflows may be explored as a separate mode only after scope/authorization controls exist. They should not define the core architecture, should never silently expand target scope, and should not weaken the repository-first defensive defaults.
