# Scanner operational reporting boundary

SynSec treats scanner findings and scanner operational diagnostics as different trust domains.

## Findings and evidence

Scanner findings are evidence-bearing product data. The engine does not apply the operational-text sanitizer to finding titles, locations, structured metadata, or source evidence. Scanner adapters remain responsible for producing valid finding data, and downstream report/lifecycle logic preserves that evidence for review.

Some finding metadata keys are reserved for SynSec-derived repository intelligence. Scanner-provided values under `dependencyUsage`, `repositoryContext`, `routeFlow`, or `routeProtection` are discarded before engine enrichment so an adapter cannot impersonate context that SynSec claims to have derived itself. Other scanner-owned metadata is preserved. Secret findings remain outside repository-context enrichment, but the same reserved-key stripping applies so a secret scanner cannot inject forged engine-owned context into a report.

## Operational diagnostics

Scanner errors and diagnostic strings are for operators, not an evidence channel. Before those strings cross the scan-engine boundary, SynSec:

- removes control characters that are unsafe in logs and terminals;
- redacts common GitHub tokens, AWS access keys, JWT-shaped credentials, authorization headers, API/auth tokens, passwords, credential-bearing URLs, and sensitive URL query parameters;
- bounds each diagnostic through the shared `sanitizeOperationalText()` policy;
- retains at most 1,000 diagnostic entries from a successful scanner result and adds an aggregate omission notice when that limit is exceeded;
- sanitizes a thrown scanner error before storing it in `ScanEngineOutcome.failures` or including it in the aggregate "all scanners failed" exception;
- re-sanitizes unavailable-scanner reasons before composing the aggregate unavailable-scanner error.

This is defense in depth. Built-in adapters already sanitize subprocess stderr and availability/version output, but the engine must not depend on every adapter preserving that invariant forever.

## What this does not do

This boundary is not a scanner sandbox. It does not make repository code safe to execute, grant a scanner network access, inspect container policy, or certify a third-party scanner. Production deployments still need externally enforced filesystem, process, credential, resource, and network isolation.

The diagnostic sanitizer also must not be used as a substitute for evidence handling. Secret findings intentionally retain the narrow evidence structures required by the scanner/report contract; operators should continue to treat reports containing secret findings as sensitive artifacts.
