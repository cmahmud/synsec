# Scanner isolation contract

SynSec treats external scanner binaries as untrusted subprocesses. The scanner SDK already minimizes inherited environment variables, bounds stdout/stderr retention, supports timeouts and aborts, and escalates termination when a scanner does not exit. Those controls reduce credential exposure and runaway process risk, but they do not provide a production sandbox by themselves.

## Hosted deployment declaration

`validateGitHubAppDeployment()` accepts an optional `scannerIsolation` declaration describing controls enforced by the surrounding container or sandbox runtime:

- `processBoundary`: `container`, `sandbox`, or `host`;
- `cpuLimit`: whether a CPU limit is enforced;
- `memoryLimit`: whether a memory limit is enforced;
- `networkPolicy`: `none`, `egress-filtered`, or `host`; and
- `repositoryFilesystem`: `read-only` or `writable`.

Without `requireScannerIsolation`, missing or incomplete isolation is reported as warning-level deployment diagnostics. This preserves local-development workflows while making the gap visible.

Production operators should set `requireScannerIsolation: true`. Deployment readiness then fails unless scanner execution uses a container or equivalent sandbox, has both CPU and memory limits, avoids unrestricted host networking, and mounts repository source read-only.

## Network policy

Repository-first scanning does not require autonomous live-target access. A production sandbox should prefer no scanner network access when scanner data can be pre-provisioned. When a scanner genuinely requires advisory/rule/database updates, use explicit egress filtering to known package/security-data endpoints outside the scan process's target-selection logic.

Do not grant scanners general outbound access merely because the hosted SynSec service itself must communicate with GitHub. GitHub installation credentials belong to acquisition/publication transport and are not scanner inputs.

## Filesystem policy

The checked-out repository should be mounted read-only inside the scanner sandbox. If a scanner needs caches, databases, temporary files, or generated output, provide a separate bounded writable scratch/cache location. Durable GitHub App state, App private keys, webhook secrets, and installation credentials must remain outside the scanner filesystem namespace.

## What SynSec does not claim

The deployment declaration is a machine-checkable contract between SynSec startup configuration and the external runtime. SynSec does not infer that a host process is isolated, and Node's `spawn()` is not treated as a container, resource controller, firewall, or read-only mount mechanism.

A deployment that sets `requireScannerIsolation: true` should populate the declaration only from actual infrastructure configuration. Falsely declaring controls does not create them.
