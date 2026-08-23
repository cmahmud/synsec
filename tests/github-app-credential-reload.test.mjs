import assert from "node:assert/strict";
import test from "node:test";
import {
  assessSynSecGitHubAppCredentialReload,
  buildSynSecGitHubAppCredentialRotationWithReloadAssessment,
} from "@synsec/github/credential-reload";

test("credential reload completes only when every specifically expected replica is ready on the target generation", () => {
  const assessment = assessSynSecGitHubAppCredentialReload({
    kind: "webhook-secret",
    targetGeneration: "webhook-2026-08-23-a",
    expectedReplicaIds: ["synsec-0", "synsec-1"],
    replicas: [
      { replicaId: "synsec-0", loadedGeneration: "webhook-2026-08-23-a", ready: true },
      { replicaId: "synsec-1", loadedGeneration: "webhook-2026-08-23-a", ready: true },
    ],
  });

  assert.equal(assessment.complete, true);
  assert.equal(assessment.expectedReplicaCount, 2);
  assert.equal(assessment.matchedReplicaCount, 2);
  assert.equal(assessment.staleReplicaCount, 0);
  assert.equal(assessment.unreadyReplicaCount, 0);
  assert.equal(assessment.missingReplicaCount, 0);
  assert.equal(assessment.unexpectedReplicaCount, 0);
});

test("credential reload fails closed for missing, stale, unready, or unexpected replicas", () => {
  const assessment = assessSynSecGitHubAppCredentialReload({
    kind: "app-private-key",
    targetGeneration: "key-v7",
    expectedReplicaIds: ["synsec-a", "synsec-b", "synsec-c"],
    replicas: [
      { replicaId: "synsec-a", loadedGeneration: "key-v7", ready: true },
      { replicaId: "synsec-b", loadedGeneration: "key-v6", ready: false },
      { replicaId: "synsec-extra", loadedGeneration: "key-v7", ready: true },
    ],
  });

  assert.equal(assessment.complete, false);
  assert.equal(assessment.matchedReplicaCount, 1);
  assert.equal(assessment.staleReplicaCount, 1);
  assert.equal(assessment.unreadyReplicaCount, 1);
  assert.equal(assessment.missingReplicaCount, 1);
  assert.equal(assessment.unexpectedReplicaCount, 1);
});

test("equal replica counts cannot substitute an unexpected replica for a required replica", () => {
  const assessment = assessSynSecGitHubAppCredentialReload({
    kind: "webhook-secret",
    targetGeneration: "webhook-v2",
    expectedReplicaIds: ["synsec-0", "synsec-1"],
    replicas: [
      { replicaId: "synsec-0", loadedGeneration: "webhook-v2", ready: true },
      { replicaId: "synsec-2", loadedGeneration: "webhook-v2", ready: true },
    ],
  });

  assert.equal(assessment.observedReplicaCount, assessment.expectedReplicaCount);
  assert.equal(assessment.missingReplicaCount, 1);
  assert.equal(assessment.unexpectedReplicaCount, 1);
  assert.equal(assessment.complete, false);
});

test("expected replica membership is set-based rather than order-dependent", () => {
  const assessment = assessSynSecGitHubAppCredentialReload({
    kind: "webhook-secret",
    targetGeneration: "webhook-v2",
    expectedReplicaIds: ["synsec-1", "synsec-0"],
    replicas: [
      { replicaId: "synsec-0", loadedGeneration: "webhook-v2", ready: true },
      { replicaId: "synsec-1", loadedGeneration: "webhook-v2", ready: true },
    ],
  });

  assert.equal(assessment.complete, true);
});

test("rotation composition derives runtime reload acknowledgement from exact fleet observations", () => {
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
      expectedReplicaIds: ["synsec-0", "synsec-1"],
      replicas: [
        { replicaId: "synsec-0", loadedGeneration: "webhook-v2", ready: true },
        { replicaId: "synsec-2", loadedGeneration: "webhook-v2", ready: true },
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
      expectedReplicaIds: ["synsec-0", "synsec-1"],
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
      expectedReplicaIds: ["synsec-0"],
      replicas: [{ replicaId: "synsec-0", loadedGeneration: "key-v2", ready: true }],
    },
  }), /kinds must match/);
});

test("credential reload rejects duplicate expected or observed replica identifiers", () => {
  assert.throws(() => assessSynSecGitHubAppCredentialReload({
    kind: "webhook-secret",
    targetGeneration: "generation-1",
    expectedReplicaIds: ["same", "same"],
    replicas: [],
  }), /expectedReplicaIds must contain unique/);

  assert.throws(() => assessSynSecGitHubAppCredentialReload({
    kind: "webhook-secret",
    targetGeneration: "generation-1",
    expectedReplicaIds: ["same", "other"],
    replicas: [
      { replicaId: "same", loadedGeneration: "generation-1", ready: true },
      { replicaId: "same", loadedGeneration: "generation-1", ready: true },
    ],
  }), /unique replicaId/);
});

test("credential reload bounds fleet membership and identifier metadata", () => {
  assert.throws(() => assessSynSecGitHubAppCredentialReload({
    kind: "webhook-secret",
    targetGeneration: "generation-1",
    expectedReplicaIds: [],
    replicas: [],
  }), /between 1 and 1000/);

  assert.throws(() => assessSynSecGitHubAppCredentialReload({
    kind: "webhook-secret",
    targetGeneration: "generation\nAuthorization: Bearer secret",
    expectedReplicaIds: ["synsec-0"],
    replicas: [],
  }), /bounded non-secret identifier/);
});

test("credential reload rejects unknown credential kinds", () => {
  assert.throws(() => assessSynSecGitHubAppCredentialReload({
    kind: "installation-token",
    targetGeneration: "generation-1",
    expectedReplicaIds: ["synsec-0"],
    replicas: [],
  }), /reload kind/);
});
