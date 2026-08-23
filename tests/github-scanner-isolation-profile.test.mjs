import assert from "node:assert/strict";
import test from "node:test";
import {
  assessSynSecScannerIsolationProfile,
  REQUIRED_SYNSEC_SCANNER_ISOLATION_CONTROLS,
} from "@synsec/github/scanner-isolation-profile";

const completeProfile = {
  schemaVersion: 1,
  runtime: "container",
  cpuLimit: true,
  memoryLimit: true,
  networkPolicy: "none",
  repositoryReadOnly: true,
  scratchSeparated: true,
  credentialsExcluded: true,
  durableStateExcluded: true,
  privileged: false,
  hostNetwork: false,
  hostPid: false,
  hostIpc: false,
  hostSocketMounts: false,
};

test("scanner isolation profile accepts the complete production control set", () => {
  assert.deepEqual(assessSynSecScannerIsolationProfile(completeProfile), {
    complete: true,
    missing: [],
    interpretation: "declared-infrastructure-controls-not-runtime-certification",
  });
});

test("scanner isolation profile reports exact missing controls in deterministic order", () => {
  const result = assessSynSecScannerIsolationProfile({
    ...completeProfile,
    cpuLimit: false,
    repositoryReadOnly: false,
    privileged: true,
    hostNetwork: true,
  });
  assert.equal(result.complete, false);
  assert.deepEqual(result.missing, [
    "cpu-limit",
    "read-only-repository",
    "not-privileged",
    "no-host-network",
  ]);
});

test("scanner isolation profile treats an unsupported schema as wholly untrusted", () => {
  const result = assessSynSecScannerIsolationProfile({ ...completeProfile, schemaVersion: 2 });
  assert.equal(result.complete, false);
  assert.deepEqual(result.missing, [...REQUIRED_SYNSEC_SCANNER_ISOLATION_CONTROLS]);
});

test("scanner isolation profile accepts an explicitly filtered sandbox network", () => {
  const result = assessSynSecScannerIsolationProfile({
    ...completeProfile,
    runtime: "sandbox",
    networkPolicy: "egress-filtered",
  });
  assert.equal(result.complete, true);
});

test("scanner isolation profile fails closed when no declaration is supplied", () => {
  const result = assessSynSecScannerIsolationProfile(undefined);
  assert.equal(result.complete, false);
  assert.deepEqual(result.missing, [...REQUIRED_SYNSEC_SCANNER_ISOLATION_CONTROLS]);
});
