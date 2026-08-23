# GitHub App credential rotation

SynSec treats webhook-secret and GitHub App private-key rotation as explicit operator-controlled rollouts. The runtime must never silently discard the previous credential before the replacement has been deployed and externally verified.

`@synsec/github/credential-rotation` provides `buildSynSecGitHubAppCredentialRotationPlan()` as a secret-free state evaluator. It accepts only boolean operator acknowledgements and returns completed steps, remaining actions, and `readyToRetirePrevious`. It does not accept credential values, contact GitHub, reload services, change webhook settings, revoke keys, or mint installation tokens.

For hosted or multi-replica deployments, `@synsec/github/credential-reload` provides a stricter deployment-observation boundary. `assessSynSecGitHubAppCredentialReload()` requires an exact set of expected application replica identifiers. Every required replica must report the same bounded target configuration generation and be ready. Missing, stale, duplicate, unexpected, or unready replica observations fail closed. The generation and replica identifiers are deployment metadata only and must never contain credential material.

`buildSynSecGitHubAppCredentialRotationWithReloadAssessment()` is the preferred production composition API. It recomputes the reload assessment from raw replica observations and derives `runtimeReloaded` internally before invoking the existing rotation planner. This prevents a hand-authored `complete: true` object or a matching replica count from being used as reload proof.

## CLI workflow

Operators can evaluate the base state machine with `synsec-github-app rotation <rotation-state.json> [--json]`. The input file accepts only `kind` plus the boolean acknowledgement fields `replacementActivated`, `runtimeReloaded`, `externalConfigurationUpdated`, and `verificationSucceeded`. Unknown fields are rejected so credential material cannot be silently accepted by the diagnostic path.

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

The booleans are acknowledgements, not probes. They must be derived from deployment and GitHub observations rather than inferred merely because a configuration file was written. In a multi-replica production deployment, prefer the deployment-wide reload assessment rather than manually asserting `runtimeReloaded: true`.

## Deployment-wide reload assessment

A supervisor or orchestration integration must supply both the exact intended fleet membership and secret-free observations:

```ts
import {
  buildSynSecGitHubAppCredentialRotationWithReloadAssessment,
} from "@synsec/github/credential-reload";

const result = buildSynSecGitHubAppCredentialRotationWithReloadAssessment({
  rotation: {
    kind: "webhook-secret",
    replacementActivated: true,
    externalConfigurationUpdated: true,
    verificationSucceeded: true,
  },
  reload: {
    kind: "webhook-secret",
    targetGeneration: "webhook-2026-08-23-a",
    expectedReplicaIds: ["synsec-0", "synsec-1"],
    replicas: [
      { replicaId: "synsec-0", loadedGeneration: "webhook-2026-08-23-a", ready: true },
      { replicaId: "synsec-1", loadedGeneration: "webhook-2026-08-23-a", ready: true },
    ],
  },
});
```

The assessment is intentionally identity-bound rather than count-bound. The observed replica set must exactly equal `expectedReplicaIds`; every expected ID and observation ID must be unique; every expected replica must report the exact target generation; and every expected replica must be ready. A replacement observation cannot substitute for a missing required replica merely because the total count is unchanged.

The assessment returns aggregate `missingReplicaCount` and `unexpectedReplicaCount` values rather than echoing expected fleet membership. `expectedReplicaCount` is derived from the supplied identity set, eliminating a separate caller-controlled count that could drift from the topology declaration.

SynSec does not discover Kubernetes pods, inspect a service mesh, read a secret manager, or contact a deployment API here. The host integration remains responsible for producing trustworthy identity observations and for deriving `expectedReplicaIds` from the intended deployment topology rather than from whichever replicas happen to respond.

### Offline reload verifier

The same reload assessment is available to deployment automation through:

```text
synsec-github-app-reload <reload-state.json> [--json]
```

The verifier exits `0` only when the exact expected fleet is ready on the target generation, exits `2` for incomplete/stale/missing/unexpected rollout state, and exits `1` for malformed input or CLI usage. Its input file is capped at 256 KiB, must be a non-symlink regular file, and has a strict credential-free schema. Unknown top-level or per-replica fields are rejected rather than ignored.

Example input:

```json
{
  "kind": "app-private-key",
  "targetGeneration": "key-v7",
  "expectedReplicaIds": ["synsec-0", "synsec-1"],
  "replicas": [
    { "replicaId": "synsec-0", "loadedGeneration": "key-v7", "ready": true },
    { "replicaId": "synsec-1", "loadedGeneration": "key-v7", "ready": true }
  ]
}
```

Count-only declarations using `expectedReplicaCount` are intentionally rejected by the verifier. A rollout gate must identify which replicas are required, not only how many responses were observed.

Use the verifier as a rollout gate before acknowledging `runtimeReloaded` in the base rotation CLI. For programmatic production integrations, prefer `buildSynSecGitHubAppCredentialRotationWithReloadAssessment()` because it derives that acknowledgement internally.

## Webhook secret

Use a coordinated overlap:

1. Stage the replacement in SynSec's bounded two-secret verification set while retaining the previous secret.
2. Reload or roll the SynSec runtime.
3. Confirm the exact expected replica set reports the replacement configuration generation and is ready.
4. Update the webhook secret in GitHub.
5. Confirm an authenticated webhook delivery after that GitHub-side update.
6. Only when the composed planner reports `readyToRetirePrevious: true`, remove the previous secret and reload again.

Programmatic single-runtime example:

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
3. Confirm the exact expected replica set reports the replacement configuration generation and is ready.
4. Verify a fresh installation-token exchange after the rollout.
5. Only when `readyToRetirePrevious` is true, revoke the previous key in GitHub.

The planner intentionally does not model installation tokens as rotatable credentials. SynSec creates installation tokens in memory for bounded purposes and does not persist them.

## Security boundary

These APIs and the CLIs are rollout guidance and deployment-state evaluation, not runtime authorization. GitHub-issued installation-token permissions and SynSec's durable repository authorization state remain authoritative. Rotation/reload state must never broaden repository scope, grant permissions, trigger remediation, or authorize network assessment.

The reload assessment also does not certify that a secret value is correct. It proves only that the exact declared fleet observations agree on a target configuration generation. External webhook authentication or a fresh installation-token exchange is still required before the previous credential can be retired.
