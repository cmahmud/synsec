import assert from "node:assert/strict";
import test from "node:test";
import {
  assessSynSecGitHubAppCredentialReload,
  buildSynSecGitHubAppCredentialRotationWithReloadAssessment,
} from "@synsec/github/credential-reload";

test("credential reload completes only when every expected replica is ready on the target generation", () => {
  const assessment = assessSynSecGitHubAppCredentialReload({
    kind: "webhook-secret",
    targetGeneration: "webhook-2026-08-23-a",
    expectedReplicaCount: 2,
    replicas: [
      { replicaId: "synsec-0", loadedGeneration: "webhook-2026-08-23-a", ready: true },
      { replicaId: "synsec-1", loadedGeneration: "webhook-2026-08-23-a", ready: true },
    ],
  });

  assert.equal(assessment.complete, true);
  assert.equal(assessment.matchedReplicaCount, 2);
  assert.equal(assessment.staleReplicaCount, 0);
  assert.equal(assessment.unreadyReplicaCount, 0);
  assert.equal(assessment.missingReplicaCount, 0);
});

test("credential reload fails closed for missing, stale, or unready replicas", () => {
  const missing = assessSynSecGitHubAppCredentialReload({
    kind: "app-private-key",
    targetGeneration: "key-v7",
    expectedReplicaCount: 3,
    replicas: [
      { replicaId: "synsec-a", loadedGeneration: "key-v7", ready: true },
      { replicaId: "synsec-b", loadedGeneration: "key-v6", ready: false },
    ],
  });

  assert.equal(missing.complete, false);
  assert.equal(missing.matchedReplicaCount, 1);
  assert.equal(missing.staleReplicaCount, 1);
  assert.equal(missing.unreadyReplicaCount, 1);
  assert.equal(missing.missingReplicaCount, 1);
});

test("rotation composition derives runtime reload acknowledgement from raw replica observations", () => {
  const incomplete = buildSynSecGitHubAppCredentialRotationWithReloadAssessment({
    rotation: {
      kind: "webhook-secret",
      replacementActivated: true,
      externalConfigurationUpdated: true,
      verificationSucceeded: true,
    },
    reload: {
      kind: "webhook-secret",
      targetGeneration: "webhook-v2",
      expectedReplicaCount: 2,
      replicas: [
        { replicaId: "synsec-0", loadedGeneration: "webhook-v2", ready: true },
        { replicaId: "synsec-1", loadedGeneration: "webhook-v1", ready: true },
      ],
    },
  });

  assert.equal(incomplete.reload.complete, false);
  assert.equal(incomplete.rotation.readyToRetirePrevious, false);
  assert.match(incomplete.rotation.requiredActions.join("\n"), /Reload or roll the SynSec runtime/);

  const complete = buildSynSecGitHubAppCredentialRotationWithReloadAssessment({
    rotation: {
      kind: "webhook-secret",
      replacementActivated: true,
      externalConfigurationUpdated: true,
      verificationSucceeded: true,
    },
    reload: {
      kind: "webhook-secret",
      targetGeneration: "webhook-v2",
      expectedReplicaCount: 2,
      replicas: [
        { replicaId: "synsec-0", loadedGeneration: "webhook-v2", ready: true },
        { replicaId: "synsec-1", loadedGeneration: "webhook-v2", ready: true },
      ],
    },
  });

  assert.equal(complete.reload.complete, true);
  assert.equal(complete.rotation.readyToRetirePrevious, true);
});

test("rotation composition rejects mismatched credential kinds", () => {
  assert.throws(() => buildSynSecGitHubAppCredentialRotationWithReloadAssessment({
    rotation: { kind: "webhook-secret" },
    reload: {
      kind: "app-private-key",
      targetGeneration: "key-v2",
      expectedReplicaCount: 1,
      replicas: [{ replicaId: "synsec-0", loadedGeneration: "key-v2", ready: true }],
    },
  }), /kinds must match/);
});

test("credential reload rejects duplicate replica observations", () => {
  assert.throws(() => assessSynSecGitHubAppCredentialReload({
    kind: "webhook-secret",
    targetGeneration: "generation-1",
    expectedReplicaCount: 2,
    replicas: [
      { replicaId: "same", loadedGeneration: "generation-1", ready: true },
      { replicaId: "same", loadedGeneration: "generation-1", ready: true },
    ],
  }), /unique replicaId/);
});

test("credential reload bounds replica counts and identifier metadata", () => {
  assert.throws(() => assessSynSecGitHubAppCredentialReload({
    kind: "webhook-secret",
    targetGeneration: "generation-1",
    expectedReplicaCount: 1001,
    replicas: [],
  }), /between 1 and 1000/);

  assert.throws(() => assessSynSecGitHubAppCredentialReload({
    kind: "webhook-secret",
    targetGeneration: "generation\nAuthorization: Bearer secret",
    expectedReplicaCount: 1,
    replicas: [],
  }), /bounded non-secret identifier/);
});

test("credential reload rejects unknown credential kinds", () => {
  assert.throws(() => assessSynSecGitHubAppCredentialReload({
    kind: "installation-token",
    targetGeneration: "generation-1",
    expectedReplicaCount: 1,
    replicas: [],
  }), /reload kind/);
});
