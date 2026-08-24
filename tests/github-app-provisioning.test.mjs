import assert from "node:assert/strict";
import test from "node:test";
import {
  buildSynSecGitHubAppManifest,
  createSynSecGitHubAppManifestRegistration,
  validateSynSecGitHubAppManifestCallback,
} from "@synsec/github/app-provisioning";

function options(overrides = {}) {
  return {
    homepageUrl: "https://synsec.example/",
    webhookUrl: "https://synsec.example/github/webhooks",
    redirectUrl: "https://synsec.example/github/app/manifest/callback",
    setupUrl: "https://synsec.example/github/app/setup",
    name: "SynSec Production",
    description: "Repository-first defensive security",
    ...overrides,
  };
}

test("manifest provisioning uses the feature-aware least-privilege setup contract", () => {
  const manifest = buildSynSecGitHubAppManifest(options());
  assert.deepEqual(manifest.default_permissions, {
    contents: "read",
    checks: "write",
  });
  assert.deepEqual(manifest.default_events, [
    "installation",
    "installation_repositories",
    "pull_request",
    "push",
  ]);
  assert.equal(manifest.hook_attributes.active, true);
  assert.equal(manifest.public, false);
  assert.equal(manifest.setup_on_update, true);
  assert.equal("request_oauth_on_install" in manifest, false);

  const writeManifest = buildSynSecGitHubAppManifest(options({
    publishSarif: true,
    enableRemediationPullRequests: true,
  }));
  assert.deepEqual(writeManifest.default_permissions, {
    contents: "write",
    checks: "write",
    security_events: "write",
    pull_requests: "write",
  });
});

test("manifest registration emits a bounded POST contract for personal and organization ownership", () => {
  const manifest = buildSynSecGitHubAppManifest(options());
  const personal = createSynSecGitHubAppManifestRegistration({ manifest, state: "state_123" });
  assert.equal(personal.method, "POST");
  assert.equal(personal.action, "https://github.com/settings/apps/new");
  assert.equal(personal.fields.state, "state_123");
  assert.deepEqual(JSON.parse(personal.fields.manifest), manifest);
  assert.equal(personal.interpretation, "registration-request-not-provisioning-success");

  const organization = createSynSecGitHubAppManifestRegistration({
    manifest,
    organization: "SynSec-HQ",
    state: "state_456",
  });
  assert.equal(
    organization.action,
    "https://github.com/organizations/SynSec-HQ/settings/apps/new",
  );

  const generated = createSynSecGitHubAppManifestRegistration({ manifest });
  assert.match(generated.fields.state, /^[A-Za-z0-9_-]{40,}$/);
  assert.notEqual(generated.fields.state, createSynSecGitHubAppManifestRegistration({ manifest }).fields.state);
});

test("manifest callback validation requires matching state and never treats callback presence as conversion success", () => {
  const callback = validateSynSecGitHubAppManifestCallback({
    code: "temporary_manifest_code_123",
    state: "expected_state_123",
    expectedState: "expected_state_123",
  });
  assert.deepEqual(callback, {
    version: 1,
    code: "temporary_manifest_code_123",
    interpretation: "validated-callback-not-conversion-success",
  });

  assert.throws(
    () => validateSynSecGitHubAppManifestCallback({
      code: "temporary_manifest_code_123",
      state: "attacker_state",
      expectedState: "expected_state_123",
    }),
    /state does not match/,
  );
  assert.throws(
    () => validateSynSecGitHubAppManifestCallback({
      code: undefined,
      state: "expected_state_123",
      expectedState: "expected_state_123",
    }),
    /missing code or state/,
  );
});

test("manifest provisioning fails closed on unsafe URLs and invalid setup/update combinations", () => {
  assert.throws(
    () => buildSynSecGitHubAppManifest(options({ webhookUrl: "http://synsec.example/github/webhooks" })),
    /absolute HTTPS URL/,
  );
  assert.throws(
    () => buildSynSecGitHubAppManifest(options({ redirectUrl: "https://user:pass@synsec.example/callback" })),
    /without credentials or a fragment/,
  );
  assert.throws(
    () => buildSynSecGitHubAppManifest(options({ setupUrl: undefined, setupOnUpdate: true })),
    /requires a setup URL/,
  );
  assert.throws(
    () => createSynSecGitHubAppManifestRegistration({
      manifest: buildSynSecGitHubAppManifest(options()),
      organization: "bad--org",
    }),
    /organization is invalid/,
  );
});
