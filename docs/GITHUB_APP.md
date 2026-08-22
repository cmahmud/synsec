# GitHub App integration contract

SynSec's GitHub App support is a transport and orchestration layer around the same repository-first scan engine used by the CLI and GitHub Action. Installing the App must not authorize live-target probing, arbitrary network assessment, secret exfiltration, persistence, or silent target expansion.

## Implemented primitives

`@synsec/github/app` currently provides:

- constant-time `X-Hub-Signature-256` verification over the exact request bytes;
- a 10 MiB webhook-body bound before event processing;
- normalization for `pull_request`, `push`, `installation`, and `installation_repositories` events only;
- repository identity from `repository.full_name` rather than payload-controlled clone/API URLs;
- required installation and commit identity for scan-bearing events;
- an explicit scan-trigger policy: pushes and only `opened`, `reopened`, `synchronize`, and `ready_for_review` pull-request actions may enqueue scans;
- installation-management events are bookkeeping only and never scan triggers;
- short-lived RS256 GitHub App JWT creation;
- installation-token exchange only through `https://api.github.com/app/installations/<id>/access_tokens` with redirects rejected;
- token/API errors that do not echo the App JWT.

`@synsec/github/replay-store` provides a durable local delivery-id replay store suitable for a single host or multiple worker processes sharing one filesystem. It uses bounded delivery identifiers, SHA-256-derived filenames, restrictive marker permissions, fully written/fsynced temporary records, and an atomic hard-link claim so two concurrent processes cannot both accept the same delivery or observe a partial canonical record. Retention is bounded between one hour and 30 days, expired markers can be pruned, and malformed existing records fail closed instead of being silently ignored. An accepted claim can also be released only when its exact delivery id and `receivedAt` still match the current unexpired marker; this lets a webhook handler return an error and allow GitHub retry after downstream durable processing fails without letting a stale worker delete a newer re-claim.

`@synsec/github/installation-store` provides bounded durable installation authorization state. It persists only installation id, account identity/type, repository-selection mode, selected `owner/name` repository identifiers when selection is limited, suspension state, and update time. It deliberately has no fields for installation tokens, App private keys, webhook secrets, clone URLs, or repository credentials. Suspended or absent installations cannot authorize a repository scan.

`@synsec/github/installation-sync` verifies and normalizes installation-management payloads into the minimal authorization model. Creation, deletion, suspension, unsuspension, and selected-repository add/remove events update durable state without persisting GitHub URLs, permissions, tokens, or arbitrary payload fields. Repository deltas fail closed when stored installation/account state is missing or inconsistent. A fresh `created` event replaces any stale selected-repository list rather than inheriting authorization left from an older record.

`@synsec/github/scan-queue` provides a bounded durable local queue for commit-pinned scan work. Jobs contain only delivery id, installation/repository identity, exact head/base commit identity, PR identity when applicable, queue timestamps, lease state, and retry count. They do not contain GitHub tokens, clone URLs, App credentials, scanner output, source snippets, or arbitrary outbound targets. Workers lease jobs for a bounded period; expired leases can be reclaimed, failed jobs are retained for operator visibility, and attempt counts are bounded.

`@synsec/github/app-handler` composes signature verification, replay claiming, installation-state synchronization, durable authorization, and queue dispatch in one tested boundary. Duplicate authenticated deliveries do not mutate installation state or enqueue duplicate work; installation-management events remain bookkeeping-only. If durable synchronization or queue dispatch fails after an accepted replay claim, the handler releases exactly that still-current claim before propagating the error so the delivery can be retried instead of being silently consumed.

`@synsec/github/repository-acquisition` materializes one exact commit from a strict `owner/name` identity through a fixed `https://github.com/<owner>/<repo>.git` transport. It rejects URL-shaped repository identities before URL construction, disables system/global Git configuration and `file://` transport so local rewrite rules cannot redirect the request, keeps the installation token out of argv and repository config, skips Git LFS smudging/submodule initialization, checks out detached `FETCH_HEAD`, verifies the resulting HEAD against the requested SHA, and removes failed temporary workspaces.

`@synsec/github/app-worker` consumes at most one leased queue job, rechecks installation authorization at execution time, acquires a short-lived token only for transport, scans the exact-commit workspace through an injected repository-scan runner, requires the resulting report to bind to the queued head SHA, obtains a fresh publication token, publishes through an injected GitHub transport, and acknowledges the queue only after publication succeeds. A repository removed or suspended after queueing is failed before credentials or source are acquired. Other worker failures return the job to the bounded retry queue.

`@synsec/github/app-worker-runner` is the production-oriented local composition over that worker boundary. It runs the existing `runScanEngine()` against the acquired exact-commit workspace, builds a check from the normalized queue repository/head context, publishes through the fixed Checks API transport, and can upload the same commit-bound report as SARIF. Pull-request jobs currently use a full repository scan at this layer; SynSec does not invent a changed-file baseline from a branch name when the exact base commit has not also been acquired.

These primitives still do **not** constitute a complete hosted GitHub App product by themselves. A minimal HTTPS server, concrete App-JWT/private-key configuration, process/container isolation, operational secret management, setup UX, and shared transactional persistence for multi-host deployments remain required.

## Webhook boundary

Webhook consumers must preserve the raw request bytes until signature verification is complete. Do not parse and reserialize JSON before verifying the signature.

After verification, callers should use the normalized event rather than payload URLs as the security boundary. Repository checkout and API publication derive from validated GitHub installation/repository identity through fixed GitHub transports. A `clone_url`, `html_url`, scanner-provided URL, finding text, or other repository-controlled field must never become an arbitrary outbound target.

The preferred local composition is `handleGitHubAppWebhook()`: signature verification and event normalization happen before the replay claim; duplicate authenticated deliveries stop before synchronization/dispatch; installation-management events synchronize durable authorization state; and scan-bearing events must pass `isRepositoryAllowed()` before queueing. Installation creation/removal and repository-selection changes never authorize immediate scanner execution by themselves. A transient durable-processing error releases only the handler's exact accepted replay claim and is then propagated so the hosting layer can return failure to GitHub and receive a retry.

## Queue and worker boundary

Queue records are commit-pinned descriptors, not checkout instructions supplied by repository content. `runNextGitHubAppScanJob()` rechecks authorization after leasing so stale queued work cannot outlive a repository removal or installation suspension.

Repository acquisition accepts only a strict validated `owner/name`, installation id context supplied by the worker, and exact commit SHA. The acquisition transport is fixed to `github.com`, and Git system/global configuration is disabled to prevent `url.*.insteadOf` or other host-local configuration from silently widening the destination. Missing/unavailable commit provenance is a job failure rather than permission to substitute the default branch, a nearby commit, a webhook clone URL, or a scanner-suggested URL.

The scanner receives the checked-out workspace and queue descriptor, not the installation token. Before publication, the worker requires `report.target.commitSha` to equal the queued head SHA and obtains a fresh installation token for the publication operation. `runConfiguredGitHubAppWorkerOnce()` then uses the same repository scan engine as the CLI/Action and fixed-host Checks/SARIF publishers. Successful workspace cleanup occurs after scan/publication handling.

Leases prevent normal duplicate processing but the local queue is not a multi-host transactional lock. Horizontally scaled workers should use a shared queue with atomic claim/lease semantics.

## Authentication boundary

`createGitHubAppJwt()` signs a short-lived RS256 token from the configured App id and private key. The private key belongs to the hosted transport/runtime and must never be exposed to scanners, reports, repository code, workflow prompts, logs, or persisted finding evidence.

`createGitHubInstallationToken()` exchanges that JWT at GitHub's fixed API host. It requests no additional repository selection or permission expansion in the token request body. Resulting installation tokens should be kept only for the operation lifetime and passed only to narrowly scoped transport functions. Repository acquisition supplies its token to Git only through a child-process environment and disables inherited Git configuration; publication likewise keeps credentials outside scanner inputs and reports.

A hosted service should validate its configured GitHub App permissions explicitly and fail closed when required permissions are absent rather than requesting broader permissions dynamically.

## Required hosted-service work

A production hosted App still needs:

1. a minimal HTTPS webhook endpoint that preserves raw request bytes and invokes `handleGitHubAppWebhook()`;
2. concrete App-JWT/private-key configuration and installation-token providers for the worker;
3. exact-base acquisition/baseline composition for changed-file PR scans when that optimization is enabled;
4. process/container workspace isolation around scans, including OS CPU/memory limits and network policy;
5. explicit retention policy for reports, failed queue records, temporary artifacts, and operator diagnostics;
6. installation/setup UX, permission diagnostics, and recovery for configuration errors;
7. operational rotation for webhook secrets and App private keys;
8. transactional shared replay/installation/queue backends when horizontally scaled replicas do not share one durable filesystem.

Until those pieces exist, the GitHub Action remains the complete executable integration path and the App modules should be treated as tested hosting foundations rather than a deployable hosted service.
