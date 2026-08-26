# Release readiness

SynSec exposes a machine-readable release-readiness assessment so a green build is not automatically treated as evidence that the repository is taggable.

## Commands

- `npm run release:check` validates hard release invariants and reports unresolved blockers. Known blockers do not make this command fail so it can run continuously in pull-request CI.
- `npm run release:check:json` emits the same assessment as bounded JSON for release automation and operator tooling.
- `npm run release:ready` is the strict tag gate. It exits non-zero for both hard invariant errors and unresolved blockers.

The assessment intentionally distinguishes `errors` from `blockers`:

- **Errors** mean an invariant that the current release line depends on has regressed, such as dropping the Node 20/24 matrix, PostgreSQL shared-state conformance, enforced OCI isolation coverage, operator documentation, the root private-package guard, or the current Node engine policy.
- **Blockers** mean a required production/release property is explicitly not complete yet. They must prevent tagging but do not need to turn every development CI run red.

## Current reproducibility blocker

The repository currently has no committed `package-lock.json`, and CI therefore still uses `npm install`. The readiness assessment reports `dependency-lockfile-missing` and strict release readiness fails.

Do not hand-author or guess a lockfile. Generate it from the repository's verified npm dependency graph in an environment with registry access, review the resulting dependency changes, commit it, and then change every CI dependency-installation step to `npm ci`. Once a lockfile exists, the readiness checker will continue to block release until CI actually enforces it.

## Trust boundary

The checker is repository-state evidence only. It does not prove that a deployment is healthy, GitHub accepted App credentials, a migration succeeded in an operator database, a scanner image is safe, a hosted tenant is authorized, or a release artifact was deployed successfully. Those properties remain governed by their existing runtime, transactional-backend, credential, maintenance, and upgrade boundaries.

Release automation should preserve this distinction: a successful `release:ready` means the repository satisfies the encoded pre-tag invariants. It is not a substitute for deployment-specific rollout and rollback evidence.
