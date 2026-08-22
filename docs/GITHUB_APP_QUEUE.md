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

The heartbeat remains active across repository acquisition, scanning, report construction, and publication. Before GitHub publication the worker also performs an explicit fenced `assertLease()` check. Before completion or retry mutation it stops the heartbeat and waits for any in-flight renewal before checking whether the heartbeat failed.

If renewal fails, SynSec treats the worker as no longer safely authoritative. It does not silently continue as though ownership were intact. Publication/completion is blocked by the failed heartbeat or by the explicit lease assertion, and any retry mutation must still satisfy the same fence.

## Expiry and reclamation

An active unexpired lease is not claimable by another worker. Once `leaseUntil` has passed, a later `claimNext()` may reclaim the job, increments the bounded retry counter, and writes a new random `leaseId`.

The previous worker's fence is immediately stale. It cannot release, fail, complete, renew, or pass the pre-publication ownership check for the reclaimed job.

This protects against a common failure mode where a slow or paused worker resumes after another worker has already taken ownership.

## In-process enqueue and authorization ordering

The supported single-runtime implementation also serializes two read-modify-write operations whose correctness depends on ordering:

- `enqueue()` duplicate-delivery and capacity checks are serialized within one `FileGitHubScanQueue` instance, so concurrent calls in that runtime cannot both persist the same delivery id after racing the same pre-write snapshot.
- GitHub installation/repository-selection synchronization is serialized per installation id and state-store instance. Concurrent deltas for the same installation therefore observe the preceding committed authorization state instead of both deriving replacements from one stale repository set. Events for different installations remain independently concurrent.

These are deliberately in-process guarantees. They do not turn two separate Node processes, two queue/store objects over the same directory, or a shared filesystem into a transactional datastore.

## Durable-state filesystem permissions

Queue records, installation authorization state, and replay markers are written as private files. Their store directories are also created as `0700` and, on platforms with POSIX permissions, SynSec repairs a pre-existing more-permissive directory back to `0700` before writing/listing durable state. This matters because installation records can contain account/repository authorization names even though credentials and source are excluded.

This directory repair applies to the local filesystem stores only. It is not a substitute for host access controls, encrypted storage where required, or a transactional shared service for multi-host deployments.

## Operational status

The aggregate runtime status reports `queue.expiredLeases` in addition to total, pending, leased, and failed counts. An expired lease is still a durable `leased` record, so it contributes to both `leased` and `expiredLeases`; the second count identifies the subset that is already eligible for reclaim.

The status remains identity-free. It does not expose repository names, installation ids, delivery ids, commit SHAs, job ids, lease ids, source paths, or scanner output.

A non-zero `expiredLeases` value is an operator signal rather than proof of data loss. It can mean a worker process exited, was paused longer than its lease, or failed to renew. A healthy worker loop should reclaim eligible work on its next claim pass. Repeated or growing expired-lease counts should prompt inspection of worker liveness, scanner duration, resource pressure, and service supervision before operators change lease settings.

## Retry and terminal state

Recoverable worker failures release the exact currently leased job back to `pending`. Terminal authorization revocation can move the exact current lease to `failed`. Successful completion deletes only the exact current leased record after fenced validation.

Failed jobs are retained for bounded operator diagnostics and maintenance. Retention uses the separate terminal-only deletion path; it does not call successful lease acknowledgement and cannot delete pending or leased jobs.

The queue caps attempts and durable queue size. Jobs that exhaust the retry bound become failed rather than cycling indefinitely.

## Crash behavior

If a process exits without releasing its job, the durable record remains leased until `leaseUntil`. Another worker may reclaim it only after expiry. Workspace cleanup is a separate ownership-marker-based maintenance concern and does not weaken queue fencing.

The heartbeat is process-local. It is not persisted as a timer and does not survive a crash; the durable lease timestamp is the recovery boundary.

## Single-host concurrency limitation

The current file-backed queue improves stale-worker correctness with unique fencing identities and renewal, but it is still a single-host runtime foundation. Claims and enqueue duplicate/capacity checks are serialized inside one `FileGitHubScanQueue` instance; installation authorization deltas are similarly ordered within one runtime per installation.

That in-process serialization is not a cross-process lock. Independent Node processes, separate queue/store instances pointed at the same directory, shared network filesystems, and multi-host deployment are not advertised as linearizable or transactionally safe.

Production horizontal scaling still requires a transactional shared queue/state backend with atomic equivalents of:

1. unique delivery insertion and queue capacity enforcement;
2. select eligible pending/expired work;
3. compare current durable state;
4. install a unique lease fence and expiry;
5. renew only that exact fence;
6. condition terminal/retry acknowledgement on that same fence; and
7. transactionally apply installation/repository authorization deltas.

A future shared backend must preserve these semantics rather than weakening them to job-id-only acknowledgement or last-write-wins authorization updates.

Until such a backend exists, operators should keep this file queue and installation state on one host and one runtime process/store instance. Service supervision may restart that process, but operators should not run multiple independent worker/runtime processes against the same durable state directories. Do not treat shared filesystem placement as a supported substitute for transactional multi-host persistence.

## Security boundary

Queue leasing and authorization ordering do not widen scan scope or grant new repository capability. Repository authorization is rechecked after claim, acquisition stays pinned to queued exact commits, scanners do not receive GitHub credentials, and publication remains commit-bound.

The queue never authorizes autonomous live-target assessment, target expansion, persistence, secret exfiltration, or unapproved repository writes. Remediation remains a separate explicit approval-consuming workflow with distinct write credentials.
