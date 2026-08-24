# GitHub App provisioning

SynSec can generate the initial GitHub App Manifest registration request for a production deployment. This is an operator workflow, not an automatic authorization path: creating a registration request, receiving a callback, or seeing an `installation_id` in a setup redirect does not prove that a GitHub App or installation is authorized for a SynSec tenant/runtime.

## Generate a registration request

Create a non-secret JSON file:

```json
{
  "homepageUrl": "https://security.example.com/",
  "webhookUrl": "https://security.example.com/github/webhooks",
  "redirectUrl": "https://security.example.com/github/app/manifest/callback",
  "setupUrl": "https://security.example.com/github/app/setup",
  "organization": "example-org",
  "name": "SynSec Production",
  "description": "Repository-first defensive security",
  "public": false,
  "publishSarif": true,
  "enableRemediationPullRequests": false
}
```

Then run:

```sh
synsec-github-app-provision provisioning.json --json
```

The command emits a `POST` registration contract containing GitHub's registration endpoint, a generated CSRF `state`, and the serialized manifest. The manifest is derived from SynSec's feature-aware minimum permission/event contract. Remediation write permissions are never enabled unless `enableRemediationPullRequests` is explicitly true.

The provisioning config deliberately rejects unknown fields. Private keys, webhook secrets, client secrets, installation tokens, database URLs, and other credentials do not belong in this file.

## Registration handshake

GitHub's App Manifest flow requires the manifest JSON to be submitted as the `manifest` form field to the generated registration endpoint. The generated `state` must be retained in a short-lived server-side session and checked when GitHub redirects to `redirectUrl`.

Use `validateSynSecGitHubAppManifestCallback()` at that boundary. It requires both `code` and `state`, compares the state in constant time when lengths match, and returns the bounded one-time code only after validation. The result is labeled `validated-callback-not-conversion-success` because callback validation does not mean the manifest conversion has completed.

The manifest conversion endpoint returns the GitHub App id and newly generated credentials. That response is credential-bearing. Exchange and storage therefore belong to hosting code connected directly to the deployment's secret manager/service manager. SynSec's provisioning helpers intentionally do not persist, log, place in scanner environments, or include these credentials in readiness/status artifacts.

## URLs and transport

Provisioning requires absolute HTTPS URLs without embedded credentials or fragments. SynSec does not silently relax this requirement for local development because this command is intended to generate production registration state. Development operators should terminate TLS at their chosen local ingress/tunnel rather than teach the production manifest builder to accept insecure endpoints.

## Setup URL is not authorization

GitHub may append an `installation_id` to the configured setup URL after installation or repository-selection changes. Treat that query parameter as untrusted metadata. A caller can spoof it by requesting the setup URL directly. Do not mark an installation active, associate it with a hosted tenant, expose repository data, or broaden access solely from the query parameter.

Runtime authorization remains the durable installation state synchronized from verified GitHub webhooks and, for any future authenticated hosted setup flow, an independently authenticated GitHub user/installation relationship. The local sanitized dashboard boundary must not be weakened to make provisioning convenient.

## Permission changes and recovery

After registration, compare the actual App configuration with:

```sh
synsec-github-app evaluate setup.json --sarif
synsec-github-app recover setup.json --sarif
```

These commands remain diagnostics/guidance only. Permission changes in GitHub can require installation owners to approve updated access, and successful configuration changes are not evidence that a running installation token currently has the requested permissions. Runtime token permission diagnostics remain authoritative for worker operations.

## Security interpretation

The manifest builder enforces input bounds, HTTPS endpoints, least-privilege defaults, and CSRF callback validation. It does not prove GitHub accepted the manifest, that an installation exists, that a user controls an installation, that a credential reached every replica, or that a scanner is authorized to access a repository. Those properties require their existing runtime, shared-state, credential-reload, and installation-authorization checks.
