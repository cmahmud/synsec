# GitHub workspace ownership and reconciliation

SynSec GitHub repository acquisition creates temporary workspaces under the configured workspace root. A normal worker removes those directories after scanning or remediation. A process crash can leave a workspace behind, so cleanup must distinguish SynSec-owned source trees from unrelated operator data before deleting anything.

## Ownership marker

Each acquisition workspace is created with the `synsec-github-` prefix and immediately receives a restrictive `.synsec-workspace.json` marker before Git runs. The marker contains only a schema version, a random workspace id, and its creation timestamp. It deliberately contains no repository name, commit SHA, installation id, token, source path, or GitHub URL.

If marker creation fails, acquisition removes the just-created directory and stops. Normal acquisition failure and normal worker cleanup continue to remove the whole owned workspace.

## Reconciliation

`reconcileGitHubOwnedWorkspaces()` scans only direct children of one configured workspace root whose names use SynSec's acquisition prefix. Observation is the default; no directories are deleted unless `deleteOwned: true` is explicitly supplied.

A directory is eligible for stale cleanup only when all of the following remain true:

- it is a real directory, not a symlink;
- it has the expected SynSec acquisition prefix;
- its ownership marker is a regular, non-symlink file within the marker size bound;
- the marker has the exact supported schema and valid timestamp/id fields;
- the marker age exceeds the configured retention period; and
- the deletion batch has not exceeded its configured maximum.

The marker is read again immediately before deletion. If the marker changed between discovery and deletion, cleanup fails closed for that entry. Missing or malformed markers are never interpreted as proof of ownership.

Retention is bounded from one hour through 30 days, and each pass may delete at most 256 workspaces. The default retention is 24 hours and default deletion batch is 32.

## Runtime maintenance

`createLocalGitHubAppRuntime().runMaintenance()` includes workspace reconciliation alongside replay-record and failed-job retention. Runtime workspace deletion remains off by default. Operators must explicitly set `deleteStaleOwnedWorkspaces: true`; `workspaceRetentionMs` and `workspaceMaxDeletes` control the bounded policy.

The runtime maintenance result reports only aggregate counts (`inspected`, `owned`, `stale`, `deleted`, and `skipped`). It does not expose repository identities, commit SHAs, installation ids, or source paths.

## Limits

Ownership markers make cleanup materially safer than an age-based directory sweep, but they are not a substitute for host/container isolation or a shared distributed lease service. Multi-host deployments should keep workspace ownership local to the worker/container that created it or use a shared transactional ownership model before implementing cross-host deletion.
