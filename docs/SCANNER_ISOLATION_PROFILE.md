# Scanner isolation verification profile

SynSec's production scanner boundary depends on controls enforced outside the Node process. The existing GitHub App deployment preflight can require a container or equivalent sandbox, CPU and memory limits, restricted networking, and a read-only repository mount. The scanner isolation profile makes additional container-escape and credential-boundary assumptions explicit and machine-checkable without accepting secrets or infrastructure connection details.

## Profile schema

The profile is versioned and intentionally small:

```json
{
  "schemaVersion": 1,
  "runtime": "container",
  "cpuLimit": true,
  "memoryLimit": true,
  "networkPolicy": "none",
  "repositoryReadOnly": true,
  "rootFilesystemReadOnly": true,
  "scratchSeparated": true,
  "credentialsExcluded": true,
  "durableStateExcluded": true,
  "privileged": false,
  "allowPrivilegeEscalation": false,
  "runAsNonRoot": true,
  "capabilitiesDropped": true,
  "hostNetwork": false,
  "hostPid": false,
  "hostIpc": false,
  "hostSocketMounts": false
}
```

`runtime` may be `container` or `sandbox`. `networkPolicy` may be `none` or `egress-filtered`. A complete profile must also declare that repository source is read-only, the scanner root filesystem is read-only, writable scratch is separate, GitHub credentials and durable App state are outside the scanner namespace, privileged mode and privilege escalation are disabled, the scanner runs as a non-root identity with ambient/additional Linux capabilities dropped, host namespaces are not shared, and host control sockets are not mounted.

The root-filesystem and process-identity controls are deliberately separate from the repository mount. A read-only checkout does not stop a scanner from persisting into another writable container path, and a non-privileged container alone does not imply `allowPrivilegeEscalation=false`, non-root execution, or dropped capabilities. Production deployment generators should enforce all of these independently.

The profile deliberately does not contain image names, registry credentials, filesystem paths, database URLs, Kubernetes credentials, GitHub tokens, or other secret-bearing deployment data.

## Offline verification

After building the workspace, validate a profile with:

```sh
synsec-scanner-isolation scanner-isolation.json --json
```

Exit codes are designed for deployment gates:

- `0`: every required control is declared;
- `2`: one or more controls are missing or unsafe;
- `1`: the input or command line is invalid.

The CLI reads at most 64 KiB, rejects symlink input files, rejects unknown fields, and does not reflect unsupported option values. This allows a repository-controlled CI job to check a sanitized declaration without following an input symlink to an arbitrary host file.

Programmatic callers can use `assessSynSecScannerIsolationProfile()` from `@synsec/github/scanner-isolation-profile`. The assessment returns only a boolean, deterministic missing-control identifiers, and the interpretation marker `declared-infrastructure-controls-not-runtime-certification`.

## Hosted production readiness

`assessGitHubAppScannerProductionReadiness()` from `@synsec/github/scanner-production-readiness` composes the existing hosted deployment validation with the detailed profile. It always forces the legacy deployment isolation contract into strict mode even if the caller omitted `requireScannerIsolation`, then requires the versioned profile to be complete as a second independent gate.

`assertGitHubAppScannerProductionReady()` provides the same policy as a startup assertion. Failure diagnostics contain only deployment issue codes and scanner-isolation control identifiers; they do not include webhook secrets, private-key material, filesystem contents, or scanner output.

This composition is intended to prevent a production host from accidentally treating the development/advisory isolation mode as sufficient. It still validates declarations rather than inspecting the running container or orchestrator.

## Mapping to common orchestrators

A Kubernetes-style deployment would normally map these declarations to controls such as container CPU/memory limits, a read-only repository volume mount, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `runAsNonRoot: true`, and `capabilities.drop: ["ALL"]`, plus disabled host namespace sharing and an independently enforced NetworkPolicy. Docker or another sandbox runtime needs equivalent controls.

These examples are conceptual mappings, not proof that a particular manifest is safe. SynSec does not currently parse or certify Kubernetes, Docker, systemd, seccomp, AppArmor, SELinux, cgroup, or network-policy configuration.

## What the profile proves

A complete profile proves only that an operator or deployment generator supplied a declaration matching SynSec's minimum isolation contract. It does not inspect Docker, Kubernetes, systemd, a container runtime, a seccomp profile, cgroups, network policy objects, or mount tables, and it is not runtime certification.

Production systems should derive the declaration from reviewed infrastructure-as-code and independently test the deployed sandbox. Do not set controls to `true` merely to satisfy the gate.

## Defensive boundary

Repository scanning remains repository-first. Scanner isolation must not be used as a justification for autonomous live-target probing, general outbound network access, secret transport into scanner processes, persistence, or expansion beyond the repository/commit explicitly selected for the scan.
