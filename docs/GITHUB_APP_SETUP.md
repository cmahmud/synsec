# GitHub App setup and least privilege

SynSec's hosted App setup helpers describe and compare the GitHub permissions/events required by enabled repository-security features. They do not create an App, modify an installation, request broader permissions, or contact GitHub.

## CLI setup diagnostics

The packaged CLI includes a separate, offline `synsec-github-app` binary so operators can inspect and lint setup requirements without writing integration code or mixing setup logic into repository scanning.

```sh
synsec-github-app requirements
synsec-github-app requirements --sarif --remediation --json
```

`requirements` prints the feature-aware permission/event minimum. `--sarif` adds the code-scanning publication permission and `--remediation` adds only the write permissions required by the explicit approval-consuming remediation PR path.

To compare a declarative or exported setup, provide a bounded JSON document containing only `permissions` and `events`:

```json
{
  "permissions": {
    "contents": "read",
    "checks": "write"
  },
  "events": [
    "installation",
    "installation_repositories",
    "pull_request",
    "push"
  ]
}
```

Then run:

```sh
synsec-github-app evaluate ./github-app-setup.json
synsec-github-app evaluate ./github-app-setup.json --json
synsec-github-app evaluate ./github-app-setup.json --strict
```

The evaluator is offline: it does not contact GitHub, inspect repositories, accept credentials, or mutate App settings. Setup files are limited to 256 KiB. A missing required permission/event exits with code `2`. Least-privilege drift is advisory by default; `--strict` exits with code `3` when extra write grants or unused webhook subscriptions exist. Schema/input failures exit with code `1`.

The file format intentionally has no credential fields. Unknown extra top-level fields are ignored rather than consumed, and errors never reflect their values. Operators should still export only the minimal permission/event declaration shown above rather than passing raw hosting configuration into this tool.

## Feature-aware minimum

`buildSynSecGitHubAppSetupContract()` returns the minimum repository permission/event contract for the selected features.

```ts
import { buildSynSecGitHubAppSetupContract } from "@synsec/github/app-setup";

const setup = buildSynSecGitHubAppSetupContract({
  publishSarif: true,
  enableRemediationPullRequests: false,
});
```

Scan-only operation remains `contents:read` plus `checks:write`. `security_events:write` is added only when SARIF publication is enabled. `contents:write` and `pull_requests:write` are added only when approved remediation PR creation is explicitly enabled.

The required webhook events are bounded to:

- `installation`
- `installation_repositories`
- `pull_request`
- `push`

No repository name, installation id, account identity, token, commit SHA, clone URL, or credential is part of the setup contract.

## Compare an existing configuration

`evaluateSynSecGitHubAppSetup()` compares an operator-declared App permission/event configuration with SynSec's feature-aware minimum.

```ts
import { evaluateSynSecGitHubAppSetup } from "@synsec/github/app-setup";

const evaluation = evaluateSynSecGitHubAppSetup({
  permissions: {
    contents: "read",
    checks: "write",
  },
  events: [
    "installation",
    "installation_repositories",
    "pull_request",
    "push",
  ],
});
```

The result separates four cases:

- `missingPermissions`: required capability is absent or weaker than required;
- `missingEvents`: a SynSec intake event is not subscribed;
- `excessiveWritePermissions`: the App has write access SynSec does not require for the enabled features;
- `extraEvents`: the App subscribes to events SynSec does not consume.

`ready` is false only when a required permission or event is missing. Excess write permissions and extra events are least-privilege drift: they should be reviewed and normally removed, but the comparison does not pretend they make the runtime nonfunctional.

A GitHub `write` grant satisfies a SynSec `read` requirement. The reverse never does. For example, `contents:write` can acquire repository source, but it is still reported as excessive when remediation is disabled because scan-only SynSec does not need repository write access.

## Runtime authorization remains authoritative

The setup evaluator is intentionally labeled `setup-comparison-not-runtime-authorization`. It is a configuration UX tool, not proof that a particular installation currently authorizes a repository or that GitHub will issue a usable token.

At execution time SynSec still:

1. checks durable installation/repository authorization;
2. exchanges a fresh App JWT for an installation token at GitHub's fixed API host;
3. validates GitHub-reported token permissions for the exact operation purpose; and
4. keeps the token out of scanner inputs and persisted state.

This separation prevents a copied setup configuration from becoming an authorization bypass.

## Recommended setup workflow

1. Choose whether SARIF publication is enabled.
2. Keep remediation PR writes disabled unless the operator intends to use the explicit approval-consuming remediation path.
3. Print the feature-aware minimum with `synsec-github-app requirements` or build it programmatically with `buildSynSecGitHubAppSetupContract()`.
4. Configure the GitHub App permissions and events to match that minimum.
5. Compare the resulting declaration with `synsec-github-app evaluate` or `evaluateSynSecGitHubAppSetup()` and investigate both missing capability and least-privilege drift.
6. Run deployment preflight from `@synsec/github/app-deployment` before starting the listener.
7. Keep runtime permission diagnostics enabled; GitHub's issued installation token remains the final permission source of truth.

Secret rotation is documented separately in `GITHUB_APP_DEPLOYMENT.md`. Setup comparison deliberately contains no secret values and can be safely included in sanitized operator diagnostics, subject to the hosting layer's normal log policy.
