# GitHub App durable queue and lease fencing

SynSec's hosted GitHub App runtime uses a bounded local durable queue to connect verified webhook intake to commit-pinned repository scans. The queue is intentionally repository-first and transport-minimal: persisted jobs identify the authorized installation, repository, exact head/base commit provenance, delivery identity, event type, retry count, and lease state. They do not persist GitHub installation tokens, App private keys, webhook secrets, clone credentials, scanner output, source excerpts, or arbitrary outbound targets.

This document describes the queue's concurrency contract. It is not a claim that the filesystem implementation is a transactional multi-host queue.

## Claim and fencing contract

Each successful `claimNext()` creates a fresh random `leaseId` and a bounded `leaseUntil` timestamp. The `leaseId` is the fencing identity for that claim.

A worker must present the exact current `leaseId` when it:

- revalidates ownership before publication;
- renews a long-running lease;
- releases work for retry;
- marks work terminally failed; or
- acknowledges successful completion.

A stale worker cannot safely infer the current fence from the retry count. Every new claim receives a new random id, including reclamation after lease expiry. Mutations fail closed when the stored job is no longer leased, the fence does not match, or the lease has already expired.

The queue's `attempts` field remains a bounded retry counter. It is operational metadata, not a lock token.

## Long-running worker renewal

The production file queue exposes its configured `leaseMs` and a fenced `renew()` operation. The hosted worker starts a heartbeat after claim and renews the exact current fence approximately every one-third of the lease duration, with a one-second minimum interval.

Renewal does not create a new claim and does not change the fence. It only extends `leaseUntil` for the currently owned lease after revalidating the stored `leaseId` and expiry state.

The heartbeat remains active across repository acquisition, scanning, report construction, and publication. Before GitHub publication the worker also performs an explicit fenced `assertLease()` check. Before completion or retry mutation it stops the heartbeat and checks whether any renewal failed.

If renewal fails, SynSec treats the worker as no longer safely authoritative. It does not silently continue as though ownership were intact. Publication/completion is blocked by the failed heartbeat or by the explicit lease assertion, and any retry mutation must still satisfy the same fence.

## Expiry and reclamation

An active unexpired lease is not claimable by another worker. Once `leaseUntil` has passed, a later `claimNext()` may reclaim the job, increments the bounded retry counter, and writes a new random `leaseId`.

The previous worker's fence is immediately stale. It cannot release, fail, complete, renew, or pass the pre-publication ownership check for the reclaimed job.

This protects against a common failure mode where a slow or paused worker resumes after another worker has already taken ownership.

## Retry and terminal state

Recoverable worker failures release the exact currently leased job back to `pending`. Terminal authorization revocation can move the exact current lease to `failed`. Successful completion deletes only the exact current leased record after fenced validation.

Failed jobs are retained for bounded operator diagnostics and maintenance. Retention uses the separate terminal-only deletion path; it does not call successful lease acknowledgement and cannot delete pending or leased jobs.

The queue caps attempts and durable queue size. Jobs that exhaust the retry bound become failed rather than cycling indefinitely.

## Crash behavior

If a process exits without releasing its job, the durable record remains leased until `leaseUntil`. Another worker may reclaim it only after expiry. Workspace cleanup is a separate ownership-marker-based maintenance concern and does not weaken queue fencing.

The heartbeat is process-local. It is not persisted as a timer and does not survive a crash; the durable lease timestamp is the recovery boundary.

## Single-host concurrency limitation

The current file-backed queue improves stale-worker correctness with unique fencing identities and renewal, but it is still a single-host runtime foundation. Filesystem read/replace operations are not advertised as a linearizable distributed transaction protocol across independent hosts or shared network filesystems.

Production horizontal scaling still requires a transactional shared queue/state backend with an atomic equivalent of:

1. select eligible pending/expired work;
2. compare current durable state;
3. install a unique lease fence and expiry;
4. renew only that exact fence; and
5. condition terminal/retry acknowledgement on that same fence.

A future shared backend must preserve these semantics rather than weakening them to job-id-only acknowledgement.

Until such a backend exists, operators should keep this file queue on one host and use service supervision for worker concurrency on that host. Do not treat shared filesystem placement as a supported substitute for transactional multi-host persistence.

## Security boundary

Queue leasing does not widen scan scope or grant new repository capability. Repository authorization is rechecked after claim, acquisition stays pinned to queued exact commits, scanners do not receive GitHub credentials, and publication remains commit-bound.

The queue never authorizes autonomous live-target assessment, target expansion, persistence, secret exfiltration, or unapproved repository writes. Remediation remains a separate explicit approval-consuming workflow with distinct write credentials.
