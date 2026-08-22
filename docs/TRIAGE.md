# Finding triage and collaboration metadata

SynSec keeps deterministic scanner evidence separate from human review metadata. Local triage state, ownership, and review comments can help a team organize findings without rewriting what a scanner observed.

## Lifecycle state

List current lifecycle records:

```sh
synsec triage .synsec/report.json --list
```

Set an explicit lifecycle state:

```sh
synsec triage .synsec/report.json <fingerprint> confirmed --note "validated during review"
```

Supported scanner-independent lifecycle states are `new`, `confirmed`, `false-positive`, `accepted-risk`, `fixed`, and `regressed`. Automatic reconciliation remains evidence-aware: changed-file scans do not mark findings outside their covered paths fixed.

## Ownership

Assign an owner to a finding that exists in the supplied report:

```sh
synsec triage .synsec/report.json <fingerprint> owner --note appsec
```

Clear ownership with an explicit empty value:

```sh
synsec triage .synsec/report.json <fingerprint> owner --note=
```

Ownership is bounded triage metadata only. It survives lifecycle state transitions and rescans, but it is not scanner evidence and does not authorize repository writes or external actions.

## Review comments

Append a local review comment:

```sh
synsec triage .synsec/report.json <fingerprint> comment --note "verify authorization boundary before accepting risk"
```

Comments are stored separately from lifecycle state in `review-comments.json` next to the selected lifecycle store. They are append-only, bounded, atomically written with restrictive local permissions where supported, and require the fingerprint to exist in the supplied report. SynSec does not automatically copy source excerpts, scanner diagnostics, tokens, or repository credentials into the comment store.

`--list` displays the current owner and comment count for each current lifecycle finding. It does not print comment bodies by default, which keeps routine terminal output compact and avoids unnecessarily redisplaying human-entered review notes.

## Custom lifecycle store path

Use `--store <file>` to select a lifecycle store explicitly:

```sh
synsec triage report.json <fingerprint> confirmed --store .synsec/team-lifecycle.json
```

The associated review-comment store remains `review-comments.json` in the same directory as that lifecycle file. This keeps the two forms of human metadata colocated while preserving separate schemas and update semantics.

## Scope

This is a local/single-host collaboration foundation, not a multi-user authorization service. There are no silent notifications, remote comment synchronization, repository mutations, or external target actions. A future hosted collaboration layer will need authentication, authorization, concurrency/transaction semantics, audit retention policy, and explicit deployment controls rather than treating these local files as a shared multi-tenant database.
