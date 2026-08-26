import assert from "node:assert/strict";
import test from "node:test";
import {
  assessSynSecGitHubAppFreshCredentialReload,
  buildSynSecGitHubAppCredentialRotationWithFreshReloadAssessment,
} from "@synsec/github/credential-reload-freshness";

const assessedAt = "2026-08-23T14:30:00.000Z";

function freshReplica(replicaId, observedAt = "2026-08-23T14:29:30.000Z") {
  return {
    replicaId,
    loadedGeneration: "webhook-v3",
    ready: true,
    observedAt,
  };
}

test("fresh credential reload requires complete recent observations for the exact fleet", () => {
  const assessment = assessSynSecGitHubAppFreshCredentialReload({
    kind: "webhook-secret",
    targetGeneration: "webhook-v3",
    expectedReplicaIds: ["synsec-0", "synsec-1"],
    replicas: [freshReplica("synsec-0"), freshReplica("synsec-1")],
    assessedAt,
  });

  assert.equal(assessment.reload.complete, true);
  assert.equal(assessment.complete, true);
  assert.equal(assessment.maxObservationAgeSeconds, 300);
  assert.equal(assessment.freshReplicaCount, 2);
  assert.equal(assessment.expiredObservationCount, 0);
  assert.equal(assessment.futureObservationCount, 0);
});

test("expired fleet observations fail closed even when generation and readiness match", () => {
  const assessment = assessSynSecGitHubAppFreshCredentialReload({
    kind: "webhook-secret",
    targetGeneration: "webhook-v3",
    expectedReplicaIds: ["synsec-0", "synsec-1"],
    replicas: [
      freshReplica("synsec-0"),
      freshReplica("synsec-1", "2026-08-23T14:20:00.000Z"),
    ],
    assessedAt,
  });

  assert.equal(assessment.reload.complete, true);
  assert.equal(assessment.expiredObservationCount, 1);
  assert.equal(assessment.complete, false);
});

test("observations too far in the future fail closed while small clock skew is tolerated", () => {
  const tolerated = assessSynSecGitHubAppFreshCredentialReload({
    kind: "webhook-secret",
    targetGeneration: "webhook-v3",
    expectedReplicaIds: ["synsec-0"],
    replicas: [freshReplica("synsec-0", "2026-08-23T14:30:20.000Z")],
    assessedAt,
  });
  assert.equal(tolerated.complete, true);

  const rejected = assessSynSecGitHubAppFreshCredentialReload({
    kind: "webhook-secret",
    targetGeneration: "webhook-v3",
    expectedReplicaIds: ["synsec-0"],
    replicas: [freshReplica("synsec-0", "2026-08-23T14:31:00.000Z")],
    assessedAt,
  });
  assert.equal(rejected.futureObservationCount, 1);
  assert.equal(rejected.complete, false);
});

test("freshness bounds are explicit and deterministic", () => {
  assert.throws(() => assessSynSecGitHubAppFreshCredentialReload({
    kind: "webhook-secret",
    targetGeneration: "webhook-v3",
    expectedReplicaIds: ["synsec-0"],
    replicas: [freshReplica("synsec-0")],
    assessedAt,
    maxObservationAgeSeconds: 9,
  }), /between 10 and 3600/);

  assert.throws(() => assessSynSecGitHubAppFreshCredentialReload({
    kind: "webhook-secret",
    targetGeneration: "webhook-v3",
    expectedReplicaIds: ["synsec-0"],
    replicas: [freshReplica("synsec-0")],
    assessedAt,
    maxObservationAgeSeconds: 3601,
  }), /between 10 and 3600/);
});

test("timestamps must be canonical UTC RFC 3339 values", () => {
  assert.throws(() => assessSynSecGitHubAppFreshCredentialReload({
    kind: "webhook-secret",
    targetGeneration: "webhook-v3",
    expectedReplicaIds: ["synsec-0"],
    replicas: [freshReplica("synsec-0")],
    assessedAt: "2026-08-23T10:30:00-04:00",
  }), /canonical UTC/);

  assert.throws(() => assessSynSecGitHubAppFreshCredentialReload({
    kind: "webhook-secret",
    targetGeneration: "webhook-v3",
    expectedReplicaIds: ["synsec-0"],
    replicas: [freshReplica("synsec-0", "not-a-timestamp")],
    assessedAt,
  }), /RFC 3339/);
});

test("rotation cannot retire the previous credential on stale reload evidence", () => {
  const assessment = buildSynSecGitHubAppCredentialRotationWithFreshReloadAssessment({
    rotation: {
      kind: "webhook-secret",
      replacementActivated: true,
      externalConfigurationUpdated: true,
      verificationSucceeded: true,
    },
    reload: {
      kind: "webhook-secret",
      targetGeneration: "webhook-v3",
      expectedReplicaIds: ["synsec-0"],
      replicas: [freshReplica("synsec-0", "2026-08-23T14:20:00.000Z")],
      assessedAt,
    },
  });

  assert.equal(assessment.reload.reload.complete, true);
  assert.equal(assessment.reload.complete, false);
  assert.equal(assessment.rotation.readyToRetirePrevious, false);
  assert.match(assessment.rotation.requiredActions.join("\n"), /Reload or roll the SynSec runtime/);
});

test("rotation retirement can proceed only after fresh fleet reload and external verification", () => {
  const assessment = buildSynSecGitHubAppCredentialRotationWithFreshReloadAssessment({
    rotation: {
      kind: "webhook-secret",
      replacementActivated: true,
      externalConfigurationUpdated: true,
      verificationSucceeded: true,
    },
    reload: {
      kind: "webhook-secret",
      targetGeneration: "webhook-v3",
      expectedReplicaIds: ["synsec-0", "synsec-1"],
      replicas: [freshReplica("synsec-0"), freshReplica("synsec-1")],
      assessedAt,
    },
  });

  assert.equal(assessment.reload.complete, true);
  assert.equal(assessment.rotation.readyToRetirePrevious, true);
});

test("fresh rotation composition rejects mismatched credential kinds", () => {
  assert.throws(() => buildSynSecGitHubAppCredentialRotationWithFreshReloadAssessment({
    rotation: { kind: "app-private-key" },
    reload: {
      kind: "webhook-secret",
      targetGeneration: "webhook-v3",
      expectedReplicaIds: ["synsec-0"],
      replicas: [freshReplica("synsec-0")],
      assessedAt,
    },
  }), /kinds must match/);
});
