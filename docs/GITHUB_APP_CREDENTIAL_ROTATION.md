# GitHub App credential rotation

SynSec treats webhook-secret and GitHub App private-key rotation as explicit operator-controlled rollouts. The runtime must never silently discard the previous credential before the replacement has been deployed and externally verified.

`@synsec/github/credential-rotation` provides `buildSynSecGitHubAppCredentialRotationPlan()` as a secret-free state evaluator. It accepts only boolean operator acknowledgements and returns completed steps, remaining actions, and `readyToRetirePrevious`. It does not accept credential values, contact GitHub, reload services, change webhook settings, revoke keys, or mint installation tokens.

## CLI workflow

Operators can evaluate the same state machine with `synsec-github-app rotation <rotation-state.json> [--json]`. The input file accepts only `kind` plus the boolean acknowledgement fields `replacementActivated`, `runtimeReloaded`, `externalConfigurationUpdated`, and `verificationSucceeded`. Unknown fields are rejected so credential material cannot be silently accepted by the diagnostic path.

An incomplete rollout exits `2` and explicitly keeps the previous credential active. A complete rollout exits `0` and reports `readyToRetirePrevious: true`.

Example webhook rotation state:

```json
{
  "kind": "webhook-secret",
  "replacementActivated": true,
  "runtimeReloaded": true,
  "externalConfigurationUpdated": true,
  "verificationSucceeded": true
}
```

The booleans are acknowledgements, not probes. They must be derived from deployment and GitHub observations rather than inferred merely because a configuration file was written.

## Webhook secret

Use a coordinated overlap:

1. Stage the replacement in SynSec's bounded two-secret verification set while retaining the previous secret.
2. Reload or roll the SynSec runtime.
3. Update the webhook secret in GitHub.
4. Confirm an authenticated webhook delivery after that GitHub-side update.
5. Only when the planner reports `readyToRetirePrevious: true`, remove the previous secret and reload again.

Programmatic example:

```ts
import { buildSynSecGitHubAppCredentialRotationPlan } from "@synsec/github/credential-rotation";

const plan = buildSynSecGitHubAppCredentialRotationPlan({
  kind: "webhook-secret",
  replacementActivated: true,
  runtimeReloaded: true,
  externalConfigurationUpdated: true,
  verificationSucceeded: true,
});
```

## GitHub App private key

Private-key rotation uses a different ordering because GitHub can keep more than one App key active:

1. Activate the replacement private key in GitHub.
2. Roll SynSec with the replacement key.
3. Verify a fresh installation-token exchange after the rollout.
4. Only when `readyToRetirePrevious` is true, revoke the previous key in GitHub.

The planner intentionally does not model installation tokens as rotatable credentials. SynSec creates installation tokens in memory for bounded purposes and does not persist them.

## Security boundary

This API and CLI are rollout guidance, not runtime authorization. GitHub-issued installation-token permissions and SynSec's durable repository authorization state remain authoritative. Rotation state must never broaden repository scope, grant permissions, trigger remediation, or authorize network assessment.
