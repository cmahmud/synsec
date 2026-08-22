# Approved remediation pull requests

SynSec remediation remains an explicitly approved repository-write workflow. Proposal generation does not grant write permission, scan workers never receive repository-write credentials, and a remediation writer may act only on an `ApprovedRemediationExecution` whose proposal, patch hashes, approval id, and target commit have already been revalidated.

## Execution boundary

`@synsec/github/remediation-writer` consumes an approved execution plus one exact acquired worktree. Before changing the worktree it verifies local `HEAD`, queries the fixed `https://github.com/<owner>/<repo>.git` transport for the configured base ref, and requires that remote ref to still equal the approved target commit. If the base moved, remediation stops before patch application and the proposal must be regenerated and approved again.

The writer writes the already-approved patch bodies to a private temporary file, runs `git apply --cached --check`, applies to the index only, then verifies the staged `A`/`M` path set exactly equals the proposal. Renames, deletions, extra files, missing files, or operation mismatches fail closed before a commit or network write.

A successful staged patch is committed with fixed SynSec author identity and the approval timestamp as the Git author/committer date. This makes retries deterministic for the same parent/tree/message. The destination branch is derived only from the proposal id (`synsec/remediation/<proposal-prefix>`). Pushes are never forced. If that branch already exists, it is accepted only when it already points at the exact deterministic remediation commit; a conflicting branch fails closed.

After the branch is present, the writer opens the pull request only through `https://api.github.com/repos/<owner>/<repo>/pulls` with redirects rejected. The returned PR URL must remain on `github.com`.

## Hosted runtime composition

`createLocalGitHubAppRuntime()` exposes `createRemediationPullRequest()` as an explicit operator action. It is not called from webhook intake, scan dispatch, scan workers, findings, AI review, or automatic lifecycle transitions.

The runtime rechecks installation/repository authorization, requests a fresh installation token for the distinct `remediate` purpose, acquires the exact approved target commit into the configured workspace tree, invokes the approval-bound writer, and cleans that worktree afterward.

The remediation token purpose requires:

- `contents:write` for the non-force branch push; and
- `pull_requests:write` for pull-request creation.

Normal scan acquisition still requests only `contents:read`. Check publication still requests `checks:write` and optional `security_events:write`. A write-capable token is therefore not handed to scanners merely because remediation support is configured.

## Failure and retry semantics

Failures before branch push do not write to the repository. A failure after a successful branch push but before PR creation can leave the deterministic remediation branch present. Retrying the exact same approved execution is safe only if that branch still points to the deterministic remediation commit; the writer then skips the push and retries PR creation. It never overwrites a changed branch.

SynSec currently does not delete remediation branches automatically. Cleanup of abandoned remediation branches is an explicit repository-administration action, not a silent background mutation.

## Deliberate limits

The initial remediation writer supports only proposal operations already allowed by the workflow contract: file creation and modification. It does not support deletes, renames, submodule changes, `.git` metadata, arbitrary target URLs, force pushes, direct writes to the base branch, merge operations, or automatic approval.

The writer also does not run a live-target verification step. Security validation remains repository-first: CI, scanners, tests, and review can validate the remediation PR without expanding into autonomous external assessment.
