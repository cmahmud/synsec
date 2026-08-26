# GitHub App credential reload freshness

SynSec treats deployment-wide credential reload observations as short-lived evidence. Exact replica membership, matching configuration generations, and readiness are necessary, but they are not sufficient if the observations are old enough that the deployment may have changed since they were collected.

`@synsec/github/credential-reload-freshness` adds a stricter production gate on top of `@synsec/github/credential-reload`.

## Fresh assessment

`assessSynSecGitHubAppFreshCredentialReload()` requires:

- the exact expected replica identifiers;
- the target credential configuration generation;
- one unique observation per replica containing `loadedGeneration`, `ready`, and canonical UTC `observedAt` metadata;
- a canonical UTC `assessedAt` timestamp from the trusted host/orchestration clock; and
- an optional observation-age bound between 10 seconds and 1 hour. The default is 5 minutes.

Every structural rule from the base reload assessment still applies. In addition, every required observation must be within the configured age bound. Observations more than 30 seconds in the future fail closed to avoid treating materially skewed timestamps as current evidence.

Example:

```ts
import {
  buildSynSecGitHubAppCredentialRotationWithFreshReloadAssessment,
} from "@synsec/github/credential-reload-freshness";

const result = buildSynSecGitHubAppCredentialRotationWithFreshReloadAssessment({
  rotation: {
    kind: "webhook-secret",
    replacementActivated: true,
    externalConfigurationUpdated: true,
    verificationSucceeded: true,
  },
  reload: {
    kind: "webhook-secret",
    targetGeneration: "webhook-2026-08-23-b",
    expectedReplicaIds: ["synsec-0", "synsec-1"],
    replicas: [
      {
        replicaId: "synsec-0",
        loadedGeneration: "webhook-2026-08-23-b",
        ready: true,
        observedAt: "2026-08-23T14:29:30.000Z",
      },
      {
        replicaId: "synsec-1",
        loadedGeneration: "webhook-2026-08-23-b",
        ready: true,
        observedAt: "2026-08-23T14:29:35.000Z",
      },
    ],
    assessedAt: "2026-08-23T14:30:00.000Z",
  },
});
```

`runtimeReloaded` is derived internally from the fresh assessment. A structurally complete but expired fleet observation therefore cannot make the rotation planner report `readyToRetirePrevious: true`.

## Trust boundary

Timestamps are deployment metadata, not credential values. They must come from a trusted supervisor/orchestration integration; accepting an attacker-controlled `assessedAt` would defeat the freshness check. The API intentionally does not query Kubernetes, a service mesh, a secret manager, GitHub, or the host clock by itself because those integrations are deployment-specific.

Fresh reload evidence still does not prove that the replacement credential value is correct. Webhook-secret rotation must additionally verify an authenticated delivery after the GitHub-side secret update. Private-key rotation must additionally verify a fresh installation-token exchange. Only then should the previous credential be retired.

This API does not broaden repository authorization, expose secrets, reload services, revoke credentials, or perform live-target security testing.
