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

These primitives do **not** constitute a hosted GitHub App service by themselves. A server, durable installation state, scan queue/workers, checkout isolation, installation UX, and operational secret management are still required.

## Webhook boundary

Webhook consumers should preserve the raw request bytes until signature verification is complete. Do not parse and reserialize JSON before verifying the signature.

After verification, callers should use the normalized event rather than payload URLs as the security boundary. In particular, repository checkout or API publication must derive from the validated GitHub installation/repository identity through a fixed GitHub transport. A `clone_url`, `html_url`, scanner-provided URL, finding text, or other repository-controlled field must never become an arbitrary outbound target.

Only `shouldScanGitHubAppWebhook()` decides whether a normalized event belongs in the scan queue. Installation creation/removal and repository-selection changes may update installation bookkeeping, but they do not authorize immediate scanner execution by themselves.

## Authentication boundary

`createGitHubAppJwt()` signs a short-lived RS256 token from the configured App id and private key. The private key belongs to the hosted transport/runtime and must never be exposed to scanners, reports, repository code, workflow prompts, logs, or persisted finding evidence.

`createGitHubInstallationToken()` exchanges that JWT at GitHub's fixed API host. It requests no additional repository selection or permission expansion in the token request body. The resulting installation token should be kept only for the operation lifetime and passed only to narrowly scoped GitHub transport functions.

A hosted service should validate its configured GitHub App permissions explicitly and fail closed when required permissions are absent rather than requesting broader permissions dynamically.

## Required hosted-service work

A production hosted App still needs:

1. a minimal HTTPS webhook endpoint that preserves raw request bytes and calls the verified parser;
2. durable delivery-id deduplication/replay protection;
3. durable installation/repository state without storing installation tokens;
4. a bounded scan job queue and isolated checkout/worker execution;
5. repository acquisition that is installation-scoped and commit-pinned;
6. per-job resource/time limits and credential minimization;
7. publication through the existing report/check/SARIF primitives;
8. explicit retention policy for reports and scan artifacts;
9. installation/setup UX and permission diagnostics;
10. operational rotation for webhook secrets and App private keys.

Until those pieces exist, the GitHub Action remains the complete executable integration path and the App module should be treated as a tested hosting foundation rather than a deployable hosted product.
