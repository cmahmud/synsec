# GitHub App credential rotation

SynSec treats webhook-secret and GitHub App private-key rotation as explicit operator-controlled rollouts. The runtime must never silently discard the previous credential before the replacement has been deployed and externally verified.

`@synsec/github/credential-rotation` provides `buildSynSecGitHubAppCredentialRotationPlan()` as a secret-free state evaluator. It accepts only boolean operator acknowledgements and returns completed steps, remaining actions, and `readyToRetirePrevious`. It does not accept credential values, contact GitHub, reload services, change webhook settings, revoke keys, or mint installation tokens.

## Webhook secret

Use a coordinated overlap:

1. Stage the replacement in SynSec's bounded two-secret verification set while retaining the previous secret.
2. Reload or roll the SynSec runtime.
3. Update the webhook secret in GitHub.
4. Confirm an authenticated webhook delivery after that GitHub-side update.
5. Only when the planner reports `readyToRetirePrevious: true`, remove the previous secret and reload again.

Example:

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

The acknowledgements must come from deployment/GitHub observations. Do not infer them merely because a config file was written.

## GitHub App private key

Private-key rotation uses a different ordering because GitHub can keep more than one App key active:

1. Activate the replacement private key in GitHub.
2. Roll SynSec with the replacement key.
3. Verify a fresh installation-token exchange after the rollout.
4. Only when `readyToRetirePrevious` is true, revoke the previous key in GitHub.

The planner intentionally does not model installation tokens as rotatable credentials. SynSec creates installation tokens in memory for bounded purposes and does not persist them.

## Security boundary

This API is rollout guidance, not runtime authorization. GitHub-issued installation-token permissions and SynSec's durable repository authorization state remain authoritative. Rotation state must never broaden repository scope, grant permissions, trigger remediation, or authorize network assessment.
