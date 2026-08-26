# GitHub App queue lease safety

SynSec's local GitHub App queue is a bounded single-host durable work queue. Queue records are commit-pinned repository scan descriptors; they never contain GitHub tokens, App private keys, webhook secrets, scanner output, source excerpts, clone URLs, or arbitrary outbound targets.

## Unique lease fencing

Every new queue claim receives a fresh random 128-bit `leaseId` in addition to the existing attempt counter and `leaseUntil` timestamp. The lease id is the worker's fencing identity. Release, failure, completion, renewal, and the worker's pre-publication check all require the exact lease id currently persisted for that job.

This matters when work outlives a lease or two local workers race. An older worker may still finish CPU or scanner work, but once another claim has replaced its lease id it cannot release the newer claim, mark it failed, acknowledge it complete, or pass the worker's publication fence.

`attempts` remains retry/accounting metadata. It is deliberately not used as the fencing identity because two processes that read the same pending generation concurrently could derive the same next attempt number.

Legacy version-1 leased records that predate `leaseId` remain parseable so they can age out and be reclaimed. Newly claimed records always receive a lease id. A worker refuses a claimed record without a lease id rather than treating missing ownership proof as permission to proceed.

## Lease renewal

The file queue exposes `renew(jobId, leaseId)`. Renewal first validates that the supplied lease id is still current and unexpired, then extends `leaseUntil` by the queue's configured lease duration. It cannot revive an expired lease or renew a lease owned by another worker.

The hosted worker starts a bounded heartbeat when the queue exposes both `renew()` and `leaseMs` (the production `FileGitHubScanQueue` does). The heartbeat runs at approximately one third of the lease duration, with a one-second lower bound, and remains active through repository acquisition, scanning, and publication.

A renewal failure is remembered. The worker does not interrupt a scanner asynchronously or recursively delete its workspace while scanner code may still be using it; instead, it lets the current operation unwind, refuses publication/completion, stops the heartbeat, and then attempts the normal fenced retry transition. If ownership has already moved to another worker, that release also fails closed.

Before obtaining publication credentials, the worker independently revalidates the current persisted lease id. This keeps GitHub publication behind both exact report commit provenance and current queue ownership.

## Retention is a separate operation

Terminal failed-job retention does not reuse `complete()`. Completion is reserved for acknowledging the exact active lease. Retention uses a distinct `deleteFailed()` operation that first proves the record is already terminal, so maintenance cannot bypass lease fencing for pending or active work.

## What this does not claim

Lease ids and heartbeat renewal reduce stale-worker and long-scan hazards, but the local filesystem queue is not presented as a transactional multi-host queue. Its scan-job claim path is still filesystem-backed rather than a shared database transaction, and horizontally scaled replicas on separate durable volumes cannot coordinate through it.

A production multi-host backend must preserve at least these semantics atomically:

- unique delivery/job insertion or equivalent idempotency;
- claim plus fresh fencing-token creation;
- compare-and-set lease renewal;
- fenced release/failure/completion;
- bounded retry accounting and terminal retention; and
- repository/install authorization rechecks at worker execution time.

Until such a backend exists, SynSec's local queue should remain a single-host deployment primitive. The fencing contract is intended to make the required shared-backend semantics explicit rather than to overstate the guarantees of the current filesystem implementation.
