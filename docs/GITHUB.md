# GitHub integration

SynSec's GitHub integration is intentionally split into two layers:

1. **Repository security analysis** stays inside the normal scanner/report pipeline.
2. **GitHub publication** converts a completed SynSec report into GitHub-native checks, annotations, and optional SARIF/code-scanning output.

This keeps GitHub credentials out of scanners and prevents repository analysis from silently expanding into unrelated network targets.

## Current integration primitives

`@synsec/github` provides:

- GitHub Actions context detection from environment variables.
- Bounded parsing of `GITHUB_EVENT_PATH`.
- Correct pull-request head SHA selection from the event payload instead of the synthetic merge SHA.
- Pull-request number, base branch/SHA, and head branch resolution.
- Conversion of a `SynSecReport` into a check-run result.
- Source annotations for findings with file/line locations.
- Severity-aware annotation levels.
- Baseline-aware annotation filtering so PR checks can focus on new findings.
- A hard 50-annotation cap per generated payload.
- CI threshold evaluation, including an explicit `none` threshold that never fails a check.
- A narrow Checks API publisher with an injectable transport for testing.
- Completed-report publication orchestration with report/head commit binding.
- A GitHub Actions repository scan runner that reuses the normal scan engine.
- Bounded local baseline loading with optional PR-base commit validation.
- Automatic PR-base baseline generation from an exact commit already present in the local checkout.
- Fixed-host gzip/base64 SARIF publication to GitHub code scanning.
- A completed JSON report artifact path suitable for explicit retention by the caller.

The root `action.yml` packages these primitives as a composite GitHub Action. It builds the checked-in SynSec runtime, scans only the repository represented by `GITHUB_WORKSPACE`, and publishes the completed report using the caller-provided GitHub token.

## Pull-request SHA handling

GitHub Actions commonly sets `GITHUB_SHA` to a synthetic merge commit for `pull_request` workflows. Publishing a check against that SHA can make the check appear on the wrong commit or disappear when the synthetic merge ref changes.

For PR events, SynSec therefore prefers `pull_request.head.sha` from the local Actions event payload and also retains `pull_request.base.sha` for baseline validation. `loadGitHubContext()` reads `GITHUB_EVENT_PATH`, rejects non-files, refuses event payloads larger than 2 MiB, parses JSON locally, and then resolves the effective repository/commit context.

No network request is required for context detection.

## Repository scan runner

`runGitHubActionsRepositoryScan()` accepts a normal `SynSecConfig`, optional baseline, checkout root, publication settings, and caller-supplied token. The scan path deliberately reuses `runScanEngine()` rather than creating GitHub-specific scanners.

For pull requests, changed-file scanning defaults to `origin/<base branch>...HEAD`. Callers can override changed-file mode or the base ref explicitly. Push, schedule, workflow-dispatch, and other non-PR contexts default to a full repository scan.

Before publication, the runner requires the scan report to identify its commit. The publication layer refuses a report whose commit differs from the GitHub commit being annotated. This prevents a stale report from being attached to a newer PR head.

The runner does not clone arbitrary targets, expand repository scope, perform live-target probing, or create repository writes.

## Baselines

A caller can provide a baseline report in memory or as a local `baselinePath`. `loadValidatedGitHubBaseline()` bounds local baseline files to 20 MiB, parses them through the normal report reader, and by default requires the baseline report's commit to match the pull-request base SHA from the event payload. An explicit expected commit can be supplied for non-PR or synthetic contexts.

For PR runs without an explicit baseline, `autoBaseline` can generate one from the exact `pull_request.base.sha`. `scanGitHubBaseCommit()` first proves that SHA is a local Git commit, creates a temporary detached Git worktree at that commit, runs a full repository scan there, requires the generated report to identify the same commit, and removes the worktree afterward. It never invokes `git fetch`, follows a repository-supplied remote URL, or mutates the caller's checkout.

The composite Action enables this mode by default. Because SynSec intentionally does not perform an implicit network fetch, the PR base commit must already exist locally. Use `actions/checkout` with `fetch-depth: 0`, or otherwise fetch the exact base commit before SynSec. A shallow checkout that lacks the base commit fails with an explicit setup error instead of silently producing a baseline against the wrong revision.

A missing baseline commit, missing expected base commit, stale baseline, or base-scan report whose commit does not match the requested base SHA fails before head publication. SynSec does not silently treat unverifiable baseline evidence as trustworthy.

## Check conclusions

The generated check conclusion follows the configured severity threshold:

- `failure` when at least one finding meets or exceeds an enabled threshold.
- `neutral` when findings exist but none meets the enabled threshold, or `failOn` is `none`.
- `success` when the report contains no findings.

This is deliberately separate from individual scanner process exit codes. Scanner failures and scan completeness remain engine/report concerns; GitHub publishing consumes the completed normalized report.

## Inline annotations

Only findings with a concrete repository path and start line can become GitHub annotations. Paths are normalized to forward slashes and leading `./` is removed. High/critical findings map to `failure`, medium/low to `warning`, and informational/unknown findings to `notice`.

When a report includes a baseline, `buildGitHubCheck()` defaults to annotating only newly introduced findings. Persisting findings remain represented in the report summary without repeatedly flooding pull-request annotations.

## Checks API publication

`publishGitHubCheck()` posts completed check runs only to `https://api.github.com/repos/<owner>/<repo>/check-runs`. The repository comes from validated GitHub context, scanner output cannot control the request URL, redirects are rejected, and bearer tokens are not copied into returned errors.

`publishSynSecReportToGitHub()` is the higher-level completed-report path. It resolves bounded local Actions context, validates report/head commit binding, builds the deterministic check, and invokes the fixed-host publisher. It never runs scanners or discovers targets itself.

## SARIF/code scanning

`publishGitHubSarif()` converts the already-completed SynSec report to SARIF 2.1, gzip-compresses and base64-encodes it, and posts it only to `https://api.github.com/repos/<owner>/<repo>/code-scanning/sarifs`.

The publisher:

- requires the report commit to match the selected GitHub commit;
- uses `refs/pull/<number>/head` for pull requests so the ref corresponds to the PR head rather than the synthetic merge ref;
- requires a fully qualified ref outside PR contexts;
- enforces a 10 MiB compressed-payload bound;
- rejects redirects;
- keeps the token in the authorization header and redacts it from reflected error text.

SARIF publication is opt-in in the Actions runner and composite Action because repositories may not grant `security-events: write`.

## Composite GitHub Action

The root `action.yml` exposes:

- `github-token` — required publication token;
- `config-path` — optional path to `synsec.config.json` in the checked-out repository;
- `baseline-path` — optional local commit-bound baseline report;
- `auto-baseline` — PR-only local base-commit scan when no baseline path is supplied; defaults to `true`;
- `changed-only` — `auto`, `true`, or `false`;
- `publish-sarif` — optional code-scanning publication.

It returns the security score, finding count, check-run id, optional SARIF upload id, `baseline-source` (`base-scan`, `file`, `provided`, or `none`), and `report-path`. The completed JSON report is written under `RUNNER_TEMP` rather than into the checked-out repository and is chmodded to `0600` where supported. Retention remains explicit: callers decide whether to upload or discard it.

The Action intentionally does **not** silently download third-party scanner binaries. Selected scanners must already be available on `PATH`; this keeps scanner installation/version pinning explicit and avoids hiding supply-chain downloads inside the security scanner itself. A future containerized worker can improve scanner provisioning while retaining pinned artifacts and isolation.

A minimal workflow should give SynSec only the permissions it needs and preserve base history for provenance-safe PR baselines:

```yaml
permissions:
  contents: read
  checks: write
  security-events: write # only needed when publish-sarif is true

steps:
  - uses: actions/checkout@v7
    with:
      fetch-depth: 0
  # Install/pin the scanners selected by synsec.config.json here.
  - uses: cmahmud/synsec@<pinned-ref>
    with:
      github-token: ${{ secrets.GITHUB_TOKEN }}
      publish-sarif: "true"
```

Use the normal `pull_request` event for scanning pull-request code. Do **not** switch to `pull_request_target` merely to obtain a write-capable token: that event executes in the base-repository security context and can expose elevated credentials to workflows that inspect untrusted contributor code. For fork pull requests where GitHub intentionally withholds write permissions, publication should be treated as unavailable rather than weakening the trust boundary.

## Scheduled repository scans

Non-PR contexts already run a full repository scan, so scheduled scans use the same engine/publication path instead of a second orchestration implementation. `docs/examples/synsec-scheduled.yml` provides a cron + manual-dispatch template that checks out full history, runs SynSec with changed-file mode and PR auto-baselines disabled, optionally publishes SARIF, and retains the completed JSON report with `actions/upload-artifact`.

The report is not uploaded automatically by SynSec. This keeps retention policy visible in the repository workflow and lets teams choose artifact duration rather than silently persisting security evidence. Scanner installation remains explicit and should be pinned by the repository owner.

## Security boundaries

GitHub integration must preserve the repository-first defensive model:

- Tokens belong to the GitHub transport layer, never scanner input.
- Report and annotation generation must not require network access.
- Scanner output must never choose the GitHub API host or arbitrary publication URL.
- A report must not be published onto a different commit than the one it represents.
- A baseline must not be trusted for PR comparison without validated commit identity.
- Auto-baseline mode may inspect only the exact PR base commit already present in the local checkout and must not perform implicit remote fetches.
- Source excerpts are not added to GitHub annotations unless already present in normalized deterministic finding fields.
- Secret values must remain redacted before publication.
- Repository writes remain outside the scan/publication path and require explicit approval.
- Repository installation must not authorize live-target exploitation, target expansion, persistence, or secret exfiltration.

## Next implementation steps

The remaining Phase 5 work is primarily hosting/authentication and explicit remediation orchestration:

1. Add a GitHub App installation/authentication layer using the same runner/publication primitives.
2. Add explicitly approved remediation pull requests.
3. Add GitLab and Bitbucket adapters without coupling the scanner core to one host.

The deterministic packages should remain usable from both a GitHub App and GitHub Actions so the scanning core does not become hosting-provider-specific.
