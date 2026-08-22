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

`@synsec/github/replay-store` additionally provides a durable local delivery-id replay store suitable for a single host or multiple worker processes sharing one filesystem. It uses bounded delivery identifiers, SHA-256-derived filenames, restrictive marker permissions, fully written/fsynced temporary records, and an atomic hard-link claim so two concurrent processes cannot both accept the same delivery or observe a partially written canonical record. Retention is bounded between one hour and 30 days, expired markers can be pruned, and malformed existing records fail closed instead of being silently ignored.

These primitives do **not** constitute a hosted GitHub App service by themselves. A server, durable installation state, scan queue/workers, checkout isolation, installation UX, and operational secret management are still required. The local replay store is not a distributed database and should be replaced or wrapped by a transactional shared store when webhook replicas do not share a filesystem.

## Webhook boundary

Webhook consumers should preserve the raw request bytes until signature verification is complete. Do not parse and reserialize JSON before verifying the signature.

After verification, callers should use the normalized event rather than payload URLs as the security boundary. In particular, repository checkout or API publication must derive from the validated GitHub installation/repository identity through a fixed GitHub transport. A `clone_url`, `html_url`, scanner-provided URL, finding text, or other repository-controlled field must never become an arbitrary outbound target.

After signature verification and before queueing work, hosted consumers should claim the `X-GitHub-Delivery` value through replay protection. A duplicate claim within the configured retention window must be treated as already processed or already in flight, not as a reason to enqueue a second scan.

Only `shouldScanGitHubAppWebhook()` decides whether a normalized event belongs in the scan queue. Installation creation/removal and repository-selection changes may update installation bookkeeping, but they do not authorize immediate scanner execution by themselves.

## Authentication boundary

`createGitHubAppJwt()` signs a short-lived RS256 token from the configured App id and private key. The private key belongs to the hosted transport/runtime and must never be exposed to scanners, reports, repository code, workflow prompts, logs, or persisted finding evidence.

`createGitHubInstallationToken()` exchanges that JWT at GitHub's fixed API host. It requests no additional repository selection or permission expansion in the token request body. The resulting installation token should be kept only for the operation lifetime and passed only to narrowly scoped GitHub transport functions.

A hosted service should validate its configured GitHub App permissions explicitly and fail closed when required permissions are absent rather than requesting broader permissions dynamically.

## Required hosted-service work

A production hosted App still needs:

1. a minimal HTTPS webhook endpoint that preserves raw request bytes and calls the verified parser;
2. durable installation/repository state without storing installation tokens;
3. a bounded scan job queue and isolated checkout/worker execution;
4. repository acquisition that is installation-scoped and commit-pinned;
5. per-job resource/time limits and credential minimization;
6. publication through the existing report/check/SARIF primitives;
7. explicit retention policy for reports and scan artifacts;
8. installation/setup UX and permission diagnostics;
9. operational rotation for webhook secrets and App private keys;
10. a transactional replay backend when horizontally scaled webhook replicas do not share the same durable filesystem.

Until those pieces exist, the GitHub Action remains the complete executable integration path and the App module should be treated as a tested hosting foundation rather than a deployable hosted product.
