# Scanner isolation contract

SynSec treats external scanner binaries as untrusted subprocesses. The scanner SDK minimizes inherited environment variables, bounds stdout/stderr retention, supports timeouts and aborts, and escalates termination when a scanner does not exit. Those controls reduce credential exposure and runaway process risk, but they do not provide a production sandbox by themselves.

## Scanner process environment

The default scanner subprocess environment is intentionally smaller than the hosting process environment. SynSec preserves only execution/locale, temporary-directory, certificate, terminal, and cache variables needed by normal command-line tools. It does **not** implicitly pass CI/cloud/registry credentials, proxy URLs, or user configuration roots.

In particular, the default environment omits `HOME`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, and `XDG_CONFIG_HOME`. This matters because scanner-specific files under those roots can contain credentials or authenticated service configuration even when variables such as `GITHUB_TOKEN`, `NPM_TOKEN`, or cloud keys have already been removed. `XDG_CACHE_HOME` may still be inherited because it is a cache location rather than a configuration/credential root.

Default command lookup is also constrained. `PATH` entries must be absolute, and when `runProcess()` is given a scanner working directory, entries equal to or contained by that working tree are removed before spawning. Relative entries such as `.` and repository-local directories such as `node_modules/.bin` therefore cannot shadow an expected scanner command merely because the repository is the child process working directory. Normal system-level absolute scanner directories remain available.

`runProcess()` additionally rejects path-like relative executable names such as `./scanner`, `../scanner`, or `tools/scanner`. Built-in adapters use bare command names resolved through the constrained search path; callers that intentionally pin an executable may use an absolute path. This prevents a future adapter from accidentally turning repository contents into the executable boundary simply by joining a tool path relative to the scan working tree.

Adapters can supply an explicit `env` to `runProcess()` when a scanner genuinely needs additional variables. Doing so is an explicit trust decision by the adapter and bypasses the SDK's default environment and search-path allowlist for that invocation. Production adapters should add only the exact non-secret variables required, should use trusted absolute command-search directories, and must not pass GitHub App credentials or other hosting secrets to scanner processes.

This environment boundary is defense in depth, not filesystem isolation: a process running as the same host user could still discover user files through other operating-system mechanisms. Production hosting therefore still requires the external sandbox/filesystem controls described below.

## Hosted deployment declaration

`validateGitHubAppDeployment()` accepts an optional `scannerIsolation` declaration describing controls enforced by the surrounding container or sandbox runtime:

- `processBoundary`: `container`, `sandbox`, or `host`;
- `cpuLimit`: whether a CPU limit is enforced;
- `memoryLimit`: whether a memory limit is enforced;
- `networkPolicy`: `none`, `egress-filtered`, or `host`; and
- `repositoryFilesystem`: `read-only` or `writable`.

Without `requireScannerIsolation`, missing or incomplete isolation is reported as warning-level deployment diagnostics. This preserves local-development workflows while making the gap visible.

Production operators should set `requireScannerIsolation: true`. Deployment readiness then fails unless scanner execution uses a container or equivalent sandbox, has both CPU and memory limits, avoids unrestricted host networking, and mounts repository source read-only.

For a stricter production gate, use the versioned profile in [SCANNER_ISOLATION_PROFILE.md](./SCANNER_ISOLATION_PROFILE.md). It additionally makes separate scratch space, credential/state exclusion, privileged mode, host namespace sharing, and host control-socket mounts explicit. `assessGitHubAppScannerProductionReadiness()` composes that profile with the hosted deployment preflight and always forces scanner isolation into strict mode.

## Network policy

Repository-first scanning does not require autonomous live-target access. A production sandbox should prefer no scanner network access when scanner data can be pre-provisioned. When a scanner genuinely requires advisory/rule/database updates, use explicit egress filtering to known package/security-data endpoints outside the scan process's target-selection logic.

Do not grant scanners general outbound access merely because the hosted SynSec service itself must communicate with GitHub. GitHub installation credentials belong to acquisition/publication transport and are not scanner inputs.

## Filesystem policy

The checked-out repository should be mounted read-only inside the scanner sandbox. If a scanner needs caches, databases, temporary files, or generated output, provide a separate bounded writable scratch/cache location. Durable GitHub App state, App private keys, webhook secrets, and installation credentials must remain outside the scanner filesystem namespace.

## What SynSec does not claim

The deployment declaration and detailed profile are machine-checkable contracts between SynSec startup configuration and the external runtime. SynSec does not infer that a host process is isolated, and Node's `spawn()` is not treated as a container, resource controller, firewall, or read-only mount mechanism.

A deployment that sets `requireScannerIsolation: true` or supplies a complete detailed profile should populate those declarations only from actual infrastructure configuration. Falsely declaring controls does not create them.
