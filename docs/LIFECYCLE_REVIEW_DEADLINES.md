# Lifecycle exception review deadlines

SynSec lifecycle records can attach an optional `reviewAt` timestamp to human triage decisions. `@synsec/lifecycle/review-deadlines` turns those timestamps into a deterministic governance report without changing scanner evidence or lifecycle state.

The assessment intentionally treats only `accepted-risk` and `false-positive` records as reviewable exceptions. Scanner-derived states such as `new`, `confirmed`, `fixed`, and `regressed` are excluded even if they happen to carry an old review timestamp.

```ts
import { assessLifecycleReviewDeadlines } from "@synsec/lifecycle/review-deadlines";

const assessment = assessLifecycleReviewDeadlines(store, {
  now: new Date().toISOString(),
  dueSoonWindowMs: 7 * 24 * 60 * 60 * 1000,
});
```

The report classifies scheduled exception reviews as `overdue`, `due-soon`, or `scheduled` and separately counts reviewable exceptions that have no deadline. Items are ordered by deadline and then fingerprint for stable CI/reporting output.

To keep this artifact suitable for broader operational reporting, it deliberately omits lifecycle notes, owners, report identifiers, and source paths. It contains only the finding fingerprint, triage state, deadline, and derived deadline status.

The due-soon window defaults to seven days and is bounded between zero and 365 days. Invalid assessment clocks or window values fail closed.

## Aggregate policy gate

Hosted or shared CI surfaces often do not need individual finding identifiers. `@synsec/lifecycle/review-policy` therefore converts an assessment into an aggregate policy result containing only counts, deterministic violation names, the assessment generation time, and a `ready` boolean.

```ts
import { evaluateLifecycleReviewPolicy } from "@synsec/lifecycle/review-policy";

const result = evaluateLifecycleReviewPolicy(assessment, {
  failOnOverdue: true,
  failOnUnscheduled: true,
});
```

The policy gate validates that the supplied summary is internally consistent before evaluating it. Its output does not copy fingerprints, source paths, owners, notes, report ids, or individual review timestamps. It is suitable for status checks and aggregate dashboards where disclosure of per-finding governance metadata is unnecessary.

## CLI governance checks

The same assessment is available through the credential-free CLI:

```text
synsec-lifecycle-reviews .synsec/lifecycle.json
synsec-lifecycle-reviews .synsec/lifecycle.json --json
synsec-lifecycle-reviews .synsec/lifecycle.json --due-soon-days 14 --fail-overdue --fail-unscheduled
synsec-lifecycle-reviews .synsec/lifecycle.json --summary-only --json --fail-overdue --fail-unscheduled
```

`--summary-only` emits the aggregate policy projection rather than the per-finding assessment. It omits the lifecycle file path, finding fingerprints, triage states, and individual review timestamps, making it the preferred mode for shared CI logs and hosted operational surfaces.

`--fail-overdue` returns exit code `2` when at least one exception is overdue. `--fail-unscheduled` returns exit code `3` when reviewable exceptions exist without a deadline, unless the overdue policy already failed. Invalid input or unsupported options return exit code `1`. These policy codes make the command suitable for repository CI/governance workflows without changing finding state.

The CLI bounds its input file to 1 MiB before lifecycle parsing, requires that the supplied path itself be a regular file, and rejects symlinks before reading their targets. That prevents a repository-controlled path from redirecting a CI governance step to an arbitrary host file. Unknown options are rejected without reflecting their values. The CLI accepts `--now <timestamp>` for deterministic testing or scheduled policy evaluation and `--due-soon-days <0-365>` to tune the reporting window.

This API and CLI are reporting/governance surfaces only. An overdue accepted-risk or false-positive decision is not silently converted back into a scanner finding state, and SynSec does not automatically revoke a human exception. Teams can use the assessment to require re-review while preserving an explicit human decision boundary.
