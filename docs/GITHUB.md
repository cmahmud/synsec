# GitHub integration

SynSec's GitHub integration is intentionally split into two layers:

1. **Repository security analysis** stays inside the normal scanner/report pipeline.
2. **GitHub publication** converts a completed SynSec report into GitHub-native check output and annotations.

This keeps GitHub credentials out of scanners and prevents repository analysis from silently expanding into unrelated network targets.

## Current integration primitives

`@synsec/github` provides:

- GitHub Actions context detection from environment variables.
- Bounded parsing of `GITHUB_EVENT_PATH`.
- Correct pull-request head SHA selection from the event payload instead of the synthetic merge SHA.
- Pull-request number, base branch, and head branch resolution.
- Conversion of a `SynSecReport` into a check-run result.
- Source annotations for findings with file/line locations.
- Severity-aware annotation levels.
- Baseline-aware annotation filtering so PR checks can focus on new findings.
- A hard 50-annotation cap per generated payload, matching GitHub's check-run annotation request limit.
- CI threshold evaluation independent of scanner exit-code quirks.
- A narrow Checks API publisher with an injectable transport for testing.
- A completed-report publication orchestrator that resolves local Actions context, builds the deterministic check, and publishes it through the fixed-host transport.

`@synsec/github/publisher` posts completed check runs only to `https://api.github.com/repos/<owner>/<repo>/check-runs`. The repository comes from validated GitHub context, scanner output cannot control the request URL, redirects are rejected, and bearer tokens are never copied into returned errors.

`@synsec/github/orchestrator` provides `publishSynSecReportToGitHub()`. It accepts an already-completed `SynSecReport`, resolves the repository/commit from bounded local Actions context, builds the check, and invokes the publisher. It does not run scanners, discover targets, mutate repositories, or perform external assessment. If valid GitHub context cannot be resolved, it fails before any transport call.

A future GitHub App or Actions adapter should own token acquisition and installation authorization while reusing these deterministic publication primitives.

## Pull-request SHA handling

GitHub Actions commonly sets `GITHUB_SHA` to a synthetic merge commit for `pull_request` workflows. Publishing a check against that SHA can make the check appear on the wrong commit or disappear when the synthetic merge ref changes.

For PR events, SynSec therefore prefers:

```text
pull_request.head.sha
```

from the local Actions event payload. `loadGitHubContext()` reads `GITHUB_EVENT_PATH`, rejects non-files, refuses event payloads larger than 2 MiB, parses JSON locally, and then resolves the effective repository/commit context.

No network request is required for context detection.

## Check conclusions

The generated check conclusion follows the configured severity threshold:

- `failure` when at least one finding meets or exceeds the threshold.
- `neutral` when findings exist but none meets the threshold.
- `success` when the report contains no findings.

This is deliberately separate from individual scanner process exit codes. Scanner failures and scan completeness remain engine/report concerns; GitHub publishing consumes the completed normalized report.

## Inline annotations

Only findings with a concrete repository path and start line can become GitHub annotations. Paths are normalized to forward slashes and leading `./` is removed. High/critical findings map to `failure`, medium/low to `warning`, and informational/unknown findings to `notice`.

When a report includes a baseline, `buildGitHubCheck()` defaults to annotating only newly introduced findings. Persisting findings remain represented in the report summary without repeatedly flooding pull-request annotations.

## Checks API publication

`publishGitHubCheck()` accepts a completed check result, validated GitHub context, and a caller-supplied token. The publisher:

- sends one `POST` to the repository Checks API endpoint;
- uses GitHub API version `2022-11-28` by default;
- sends the token only in the `Authorization` header;
- rejects redirects;
- validates the returned check-run id;
- returns only publication metadata such as id, URL, status, and conclusion.

`publishSynSecReportToGitHub()` is the higher-level completed-report path. It preserves the same transport restrictions while removing duplicate context/check/publisher glue from future Actions and GitHub App entrypoints.

Token acquisition is intentionally outside these functions. GitHub App installation tokens, Actions `GITHUB_TOKEN`, and any future enterprise-hosting transport should remain separate concerns so credentials never enter scanners or normalized reports.

## Security boundaries

GitHub integration must preserve the repository-first defensive model:

- Tokens belong to the GitHub transport layer, never scanner input.
- Report and annotation generation must not require network access.
- Scanner output must never choose the GitHub API host or arbitrary publication URL.
- Source excerpts are not added to GitHub annotations unless already present in normalized deterministic finding fields.
- Secret values must remain redacted before publication.
- A future remediation pull-request flow must require explicit approval before repository writes.
- Repository installation must not authorize live-target exploitation, target expansion, persistence, or secret exfiltration.

## Next implementation steps

The remaining Phase 5 work is product orchestration and installation/authentication:

1. Add a GitHub App installation/authentication layer.
2. Wire PR events to changed-file scans and baseline selection.
3. Connect the completed scan result to `publishSynSecReportToGitHub()` in that PR event runner.
4. Upload SARIF to GitHub code scanning where repository permissions allow it.
5. Add scheduled repository scans.
6. Add explicitly approved remediation pull requests.

The deterministic package should remain usable from both a GitHub App and a GitHub Actions integration so the scanning core does not become hosting-provider-specific.
