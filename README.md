# SynSec

SynSec is a repository-first security scanning platform for finding, correlating, and explaining vulnerabilities before they reach production.

The project is designed around a simple idea: mature open-source scanners should do what they are already good at, while SynSec provides the orchestration, normalization, deduplication, repository context, remediation workflow, and developer experience around them.

## Status

Early development.

## Initial scope

- Scan local repositories and Git repositories.
- Normalize findings from multiple security engines into one schema.
- Correlate duplicate findings instead of dumping raw scanner output.
- Track code vulnerabilities, vulnerable dependencies, leaked secrets, infrastructure-as-code issues, and repository security posture.
- Preserve evidence, confidence, source scanner, file/line location, CWE/CVE metadata, and remediation guidance.
- Add an AI review layer later for contextual triage and fix suggestions.

## Planned scanner integrations

SynSec will begin by integrating existing engines rather than rewriting them:

- Opengrep — static analysis / SAST
- Trivy — vulnerabilities, dependencies, containers, IaC, and secrets
- Gitleaks — secret detection and Git-history scanning
- OSV-Scanner — dependency vulnerability analysis
- Syft — SBOM generation
- Grype — package and container vulnerability analysis
- Checkov — infrastructure-as-code and CI configuration scanning
- OpenSSF Scorecard — repository security posture

Additional engines can be added through a scanner adapter interface.

## Repository model

```text
repository
   |
   v
scanner adapters
   |
   +-- Opengrep
   +-- Trivy
   +-- Gitleaks
   +-- ...
   |
   v
normalized findings
   |
   v
correlation / deduplication
   |
   v
contextual review
   |
   +-- dashboard
   +-- CLI
   +-- remediation workflow
```

## Safety model

SynSec is being built primarily for defensive analysis of code and infrastructure that the operator owns or is authorized to assess. Repository scanning is the core product; external attack-surface and bug-bounty workflows are secondary and must remain explicitly authorized.

## License

License has not been selected yet.
