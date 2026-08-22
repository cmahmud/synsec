# SynSec

SynSec is a repository-first security scanner that combines mature open-source security engines into one normalized, correlated report.

Instead of replacing tools such as Opengrep, Trivy, Betterleaks, OSV-Scanner, Grype, Checkov, Syft, and OpenSSF Scorecard, SynSec runs them through a common adapter layer, merges overlapping results, preserves supporting artifacts such as SBOMs, adds repository context, tracks changes against baselines, exports developer-friendly reports, and can optionally send selected findings through an OpenAI-compatible model router for a separate review pass.

> **Current release line:** v0.2 development MVP. The repository is usable for local testing, but scanner adapters and report schemas may still change before v1.0.
