# Approved remediation pull requests

SynSec remediation remains an explicitly approved repository-write workflow. Proposal generation does not grant write permission, scan workers never receive repository-write credentials, and a remediation writer may act only on an `ApprovedRemediationExecution` whose proposal, patch hashes, approval id, and target commit are revalidated immediately before execution.

## Execution boundary

`@synsec/github/remediation-writer` consumes an approved execution plus one exact acquired worktree. It reruns the remediation authorization/integrity checks before issuing even a local Git command, so mutation of the JavaScript execution object after an earlier approval check cannot substitute different patch contents. Before changing the worktree it then verifies local `HEAD`, queries the fixed `https://github.com/<owner>/<repo>.git` transport for the configured base ref, and requires that remote ref to still equal the approved target commit. If the base moved, remediation stops before patch application and the proposal must be regenerated and approved again.

The writer writes the already-approved patch bodies to a private temporary file, runs `git apply --cached --check`, applies to the index only, then verifies the staged `A`/`M` path set exactly equals the proposal. Renames, deletions, extra files, missing files, or operation mismatches fail closed before a commit or network write.

A successful staged patch is committed with fixed SynSec author identity and the approval timestamp as the Git author/committer date. This makes retries deterministic for the same parent/tree/message. The destination branch is derived only from the proposal id (`synsec/remediation/<proposal-prefix>`). Pushes are never forced. If that branch already exists, it is accepted only when it already points at the exact deterministic remediation commit; a conflicting branch fails closed.

After the branch is present, the writer opens the pull request only through `https://api.github.com/repos/<owner>/<repo>/pulls` with redirects rejected. The returned PR URL must remain on `github.com`.

## Hosted runtime composition

`createLocalGitHubAppRuntime()` exposes `createRemediationPullRequest()` as an explicit operator action. It is not called from webhook intake, scan dispatch, scan workers, findings, AI review, or automatic lifecycle transitions.

The runtime rechecks installation/repository authorization and first requests the normal `acquire` credential, which requires only `contents:read`, to materialize the exact approved target commit. Only after acquisition succeeds does it request a fresh token for the distinct `remediate` purpose and pass that credential to the approval-bound writer. The acquired worktree is cleaned afterward even when the write operation fails.

The remediation token purpose requires:

- `contents:write` for the non-force branch push; and
- `pull_requests:write` for pull-request creation.

Normal scan and remediation-source acquisition therefore continue to use `contents:read`. Check publication still requests `checks:write` and optional `security_events:write`. The shorter-lived write-capable credential is minted only at the explicit approved write boundary and is never passed to scanners.

## GitHub App setup

`@synsec/github/app-setup` provides a feature-aware setup contract for operators. Repository scanning without remediation recommends only `contents:read` and `checks:write`, plus `security_events:write` when SARIF is enabled. `contents:write` and `pull_requests:write` appear only when `enableRemediationPullRequests` is explicitly enabled. The helper describes required permissions and webhook events; it does not create or broaden an installation.

## Failure and retry semantics

Failures before branch push do not write to the repository. A failure after a successful branch push but before PR creation can leave the deterministic remediation branch present. Retrying the exact same approved execution is safe only if that branch still points to the deterministic remediation commit; the writer then skips the push and retries PR creation. It never overwrites a changed branch.

SynSec currently does not delete remediation branches automatically. Cleanup of abandoned remediation branches is an explicit repository-administration action, not a silent background mutation.

## Deliberate limits

The initial remediation writer supports only proposal operations already allowed by the workflow contract: file creation and modification. It does not support deletes, renames, submodule changes, `.git` metadata, arbitrary target URLs, force pushes, direct writes to the base branch, merge operations, or automatic approval.

The writer also does not run a live-target verification step. Security validation remains repository-first: CI, scanners, tests, and review can validate the remediation PR without expanding into autonomous external assessment.
