import assert from "node:assert/strict";
import test from "node:test";
import { buildSynSecGitHubAppCredentialRotationPlan } from "@synsec/github/credential-rotation";

test("webhook-secret rotation fails closed until GitHub update and authenticated delivery are confirmed", () => {
  const plan = buildSynSecGitHubAppCredentialRotationPlan({
    kind: "webhook-secret",
    replacementActivated: true,
    runtimeReloaded: true,
  });

  assert.equal(plan.readyToRetirePrevious, false);
  assert.match(plan.requiredActions.join("\n"), /Update the GitHub webhook secret/);
  assert.match(plan.requiredActions.join("\n"), /authenticated GitHub webhook delivery/);
  assert.match(plan.requiredActions.at(-1), /Keep the previous webhook secret/);
  assert.equal(JSON.stringify(plan).includes("secret-value"), false);
});

test("webhook-secret rotation permits retirement only after every acknowledgement", () => {
  const plan = buildSynSecGitHubAppCredentialRotationPlan({
    kind: "webhook-secret",
    replacementActivated: true,
    runtimeReloaded: true,
    externalConfigurationUpdated: true,
    verificationSucceeded: true,
  });

  assert.equal(plan.readyToRetirePrevious, true);
  assert.deepEqual(plan.requiredActions, []);
  assert.equal(plan.completedSteps.length, 4);
});

test("private-key rotation requires activation, runtime reload, and fresh token exchange", () => {
  const incomplete = buildSynSecGitHubAppCredentialRotationPlan({
    kind: "app-private-key",
    replacementActivated: true,
    runtimeReloaded: true,
  });
  assert.equal(incomplete.readyToRetirePrevious, false);
  assert.match(incomplete.requiredActions.join("\n"), /installation-token exchange/);
  assert.match(incomplete.requiredActions.at(-1), /Keep the previous GitHub App private key active/);

  const complete = buildSynSecGitHubAppCredentialRotationPlan({
    kind: "app-private-key",
    replacementActivated: true,
    runtimeReloaded: true,
    verificationSucceeded: true,
  });
  assert.equal(complete.readyToRetirePrevious, true);
  assert.deepEqual(complete.requiredActions, []);
});

test("rotation planner rejects unknown credential kinds", () => {
  assert.throws(() => buildSynSecGitHubAppCredentialRotationPlan({
    kind: "installation-token",
  }), /credential rotation kind/);
});
