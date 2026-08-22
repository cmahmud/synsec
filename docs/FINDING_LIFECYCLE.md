# Finding lifecycle and review governance

SynSec keeps human triage decisions separate from scanner evidence. A scanner report says what tools observed. The lifecycle store records what reviewers decided about those normalized finding fingerprints.

## Lifecycle states

SynSec supports these finding states:

- `new` — observed without an earlier lifecycle decision.
- `confirmed` — a reviewer has confirmed the finding should be addressed.
- `false-positive` — a reviewer has decided the normalized finding is not actionable as reported.
- `accepted-risk` — a reviewer has explicitly accepted the risk for now.
- `fixed` — a previously actionable finding disappeared after SynSec had enough repeated scan coverage to conclude absence.
- `regressed` — a finding previously recorded as fixed has returned.

Human decisions such as `false-positive` and `accepted-risk` are preserved when later scans omit a finding. SynSec does not silently rewrite them merely because one report no longer contains the fingerprint.

Incremental scans also do not call an out-of-scope finding fixed. A disappearance is meaningful only when the affected path was covered and a detecting scanner reran.

## Ownership, notes, and comments

Lifecycle records may contain a bounded owner and note. Review comments live in a separate append-only local store. These fields are human triage metadata and are deliberately not merged into scanner evidence.

The local triage view/dashboard exposes current finding title/severity plus lifecycle state, owner, note, review deadline, and bounded review comments. It intentionally excludes source excerpts, raw scanner diagnostics, credentials, and arbitrary repository URLs.

## Review deadlines

A lifecycle record can carry an optional `reviewAt` ISO timestamp. The deadline is useful for decisions that should not remain permanent without reconsideration, especially `accepted-risk` records.

`reviewAt` does **not**:

- change finding state automatically;
- mark a finding fixed, confirmed, or regressed;
- change scan severity or confidence;
- affect GitHub check conclusions;
- count as scanner evidence; or
- trigger repository writes.

It is governance metadata only.

The sanitized triage view derives a presentation-only review status:

- `scheduled` before the deadline;
- `due` at or after the deadline.

A due deadline leaves the underlying lifecycle state unchanged. The local HTML triage dashboard labels it `Review overdue` so reviewers can prioritize it without SynSec manufacturing a security conclusion.

## CLI usage

The existing triage command can assign a review deadline using the `review-at` action and the bounded `--note` value already used for human triage metadata:

```text
synsec triage report.json <fingerprint> review-at --note 2026-11-01T12:00:00.000Z
```

Clear the deadline explicitly:

```text
synsec triage report.json <fingerprint> review-at --note clear
```

List current lifecycle records:

```text
synsec triage report.json --list
```

Records with a deadline include `review:<timestamp>` in the CLI listing. The lifecycle API also exposes `setFindingReviewAt(...)` for callers that integrate SynSec programmatically.

A state update may preserve an existing review deadline. Programmatic callers can explicitly set or clear the deadline while changing state through `setFindingState(...)`.

## Accepted-risk review pattern

A conservative workflow is:

1. confirm that the finding identity and current repository context are understood;
2. record `accepted-risk` only through an explicit human triage action;
3. record the rationale as a bounded note/comment;
4. assign an owner when one is known;
5. set a concrete `reviewAt` date;
6. revisit the decision when the deadline becomes due; and
7. rescan/verify normally if remediation is performed.

The review date is not a substitute for remediation verification. A finding is called fixed only through evidence-aware scan comparison, not because its risk-acceptance review date passed or a reviewer changed metadata.

## Persistence and privacy

The lifecycle store remains schema version 1; `reviewAt` is optional and therefore backward-compatible with existing records. Invalid timestamps fail validation rather than being accepted as ambiguous review metadata.

Lifecycle and review-comment files are local bounded metadata stores. Remediation-verification JSON is written through a private atomic-shaped output path: a restrictive temporary file is completed before rename and the final file mode is repaired to `0600` where POSIX permissions are available.

This lifecycle system does not authorize live-target testing, target expansion, persistence, secret exfiltration, or automatic repository modification. Repository-changing remediation remains a separate explicit approval-consuming workflow.
