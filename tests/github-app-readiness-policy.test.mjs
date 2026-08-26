import assert from "node:assert/strict";
import test from "node:test";
import {
  assessGitHubAppRuntimeReadiness,
  createGitHubAppRuntimeReadinessPredicate,
} from "@synsec/github/app-readiness-policy";

function status(overrides = {}) {
  return {
    installations: {
      total: 2,
      active: 2,
      suspended: 0,
      allRepositories: 1,
      selectedRepositories: 1,
      ...(overrides.installations ?? {}),
    },
    queue: {
      total: 3,
      pending: 2,
      leased: 1,
      expiredLeases: 0,
      failed: 0,
      ...(overrides.queue ?? {}),
    },
  };
}

test("hosted runtime readiness defaults to rejecting expired worker leases", () => {
  assert.equal(assessGitHubAppRuntimeReadiness(status()).ready, true);

  const assessment = assessGitHubAppRuntimeReadiness(status({
    queue: { total: 3, pending: 1, leased: 2, expiredLeases: 1, failed: 0 },
  }));
  assert.equal(assessment.ready, false);
  assert.deepEqual(assessment.codes, ["expired-leases"]);
});

test("hosted runtime readiness supports bounded deployment-specific backlog thresholds", () => {
  const assessment = assessGitHubAppRuntimeReadiness(status({
    queue: { total: 9, pending: 6, leased: 1, expiredLeases: 0, failed: 2 },
  }), {
    maxPendingJobs: 5,
    maxFailedJobs: 1,
  });

  assert.equal(assessment.ready, false);
  assert.deepEqual(assessment.codes, ["pending-backlog", "failed-backlog"]);
});

test("hosted runtime readiness fails closed on internally inconsistent aggregate status", () => {
  const cases = [
    status({ installations: { total: 3 } }),
    status({ installations: { allRepositories: 2, selectedRepositories: 2 } }),
    status({ queue: { total: 4 } }),
    status({ queue: { leased: 0, expiredLeases: 1, pending: 3 } }),
    status({ queue: { pending: -1, total: 0 } }),
  ];

  for (const candidate of cases) {
    const assessment = assessGitHubAppRuntimeReadiness(candidate);
    assert.equal(assessment.ready, false);
    assert.deepEqual(assessment.codes, ["invalid-status"]);
  }
});

test("readiness policy bounds thresholds and validates them before the first probe", () => {
  for (const invalid of [-1, 1.5, 1_000_000_001]) {
    assert.throws(() => createGitHubAppRuntimeReadinessPredicate({
      maxPendingJobs: invalid,
    }), /maxPendingJobs must be an integer/);
  }
});

test("readiness predicate integrates with the hosted listener without exposing reason codes", () => {
  const predicate = createGitHubAppRuntimeReadinessPredicate({ maxExpiredLeases: 0 });
  assert.equal(predicate(status()), true);
  assert.equal(predicate(status({
    queue: { total: 3, pending: 1, leased: 2, expiredLeases: 1, failed: 0 },
  })), false);
});
