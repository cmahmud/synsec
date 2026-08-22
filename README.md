# SynSec

SynSec is a repository-first security scanner that combines mature open-source security engines into one normalized, correlated report.

Instead of replacing tools such as Opengrep, Trivy, Betterleaks, OSV-Scanner, Grype, Checkov, and OpenSSF Scorecard, SynSec runs them through a common adapter layer, merges overlapping results, adds repository context, tracks changes against baselines, exports developer-friendly reports, and can optionally send selected findings through an OpenAI-compatible model router for a separate review pass.

> **Current release line:** v0.2 development MVP. The repository is usable for local testing, but scanner adapters and report schemas may still change before v1.0.

## What works now

- Multi-scanner repository scans with bounded concurrency.
- Scanner failure isolation: one broken engine does not destroy the whole scan.
- Protection against false "clean" reports when no scanner successfully ran.
- Opengrep SAST integration.
- Betterleaks secret scanning, with Gitleaks retained as an optional fallback.
- OSV-Scanner dependency analysis.
- Trivy vulnerability, secret, and misconfiguration analysis.
- Grype dependency/package analysis.
- Checkov IaC analysis.
- OpenSSF Scorecard repository-posture analysis.
- Scanner-independent finding schema.
- Deterministic cross-scanner correlation and deduplication.
- Repository language/framework inventory.
- Git commit, branch, and remote metadata discovery with credential redaction.
- Versioned JSON reports.
- Self-contained HTML security dashboard.
- SARIF 2.1.0 output for code-scanning systems.
- Baselines with new/fixed/persisting finding tracking.
- Configurable CI failure thresholds.
- Explicit opt-in AI finding review through an OpenAI-compatible endpoint.
- A seven-question AI review gate that keeps scanner evidence separate from model inference.

## Quick start

Requirements:

- Node.js 20 or newer (Node 24 recommended)
- npm
- at least one supported scanner binary in `PATH`

```bash
git clone https://github.com/cmahmud/synsec.git
cd synsec
npm install
npm run build

# See which engines are installed
npm run synsec -- doctor .

# Scan a repository
npm run synsec -- scan /path/to/repository
```

See [`docs/INSTALL.md`](docs/INSTALL.md) for scanner installation notes.

SynSec skips selected engines that are not installed and reports the missing coverage. If **none** of the selected engines can run, the scan fails instead of returning a misleading 100/100 score.

A normal scan writes:

```text
.synsec/
├── report.json
├── report.html
└── report.sarif
```

Open `report.html` locally for the dashboard.

## Commands

```text
synsec init [path]
synsec doctor [path]
synsec scan <path> [options]
synsec review <report.json> [options]
synsec render <report.json>
synsec baseline <report.json> [destination]
synsec version
```

Useful scan options:

```text
--scanners opengrep,betterleaks,trivy
--parallel 3
--timeout 900
--fail-on high
--baseline .synsec/baseline.json
--json
--no-write
```

Create a starter configuration with:

```bash
npm run synsec -- init .
```

That creates `synsec.config.json`.

## Default configuration

```json
{
  "schemaVersion": 1,
  "scanners": [
    "opengrep",
    "betterleaks",
    "osv-scanner",
    "trivy",
    "grype",
    "checkov",
    "scorecard"
  ],
  "parallelism": 3,
  "timeoutMs": 900000,
  "failOn": "none",
  "reports": {
    "json": ".synsec/report.json",
    "html": ".synsec/report.html",
    "sarif": ".synsec/report.sarif"
  },
  "ai": {
    "enabled": false,
    "provider": "openai-compatible",
    "sendSourceContext": false
  }
}
```

`failOn` can be `critical`, `high`, `medium`, `low`, `info`, `unknown`, or `none`. When a threshold is configured, a scan containing that severity or higher exits with code `2`, which is useful in CI.

## Scanner engines

| Engine | SynSec ID | Purpose | Default |
| --- | --- | --- | --- |
| Opengrep | `opengrep` | SAST / taint-aware static analysis | yes |
| Betterleaks | `betterleaks` | secrets and Git history | yes |
| Gitleaks | `gitleaks` | secrets and Git history fallback | no |
| OSV-Scanner | `osv-scanner` | open-source dependency vulnerabilities | yes |
| Trivy | `trivy` | dependencies, secrets, IaC/misconfiguration | yes |
| Grype | `grype` | package/dependency vulnerabilities | yes |
| Checkov | `checkov` | infrastructure-as-code | yes |
| OpenSSF Scorecard | `scorecard` | repository security posture | yes |

Betterleaks is preferred for new installs because it is the actively developed successor maintained by the Gitleaks team. SynSec does **not** enable Betterleaks live credential validation; the adapter performs repository scanning with redacted report output only.

OpenSSF Scorecard results are treated as repository-posture findings rather than definitive vulnerabilities. Perfect 10/10 checks are not manufactured into findings; non-perfect checks retain their own score and reason as metadata.

The engines stay separate projects with their own licenses. SynSec invokes installed binaries and parses their machine-readable output rather than copying their source into this repository.

## Correlation

Raw scanner output is not the product. SynSec converts each result into a common model containing, where available:

- category and severity;
- confidence;
- scanner and rule ID;
- file/line/column;
- CVE, CWE, GHSA, and OSV identifiers;
- evidence that is safe to retain;
- remediation guidance;
- scanner-specific metadata;
- native scanner fingerprint.

SynSec then computes its own correlation fingerprint. This matters because two scanners often use different rule IDs, titles, and native fingerprints for the same issue.

Current v0.2 correlation can merge:

- dependency findings sharing advisory identifiers and package identity;
- secret findings at the same file/line without hashing or retaining the secret;
- SAST findings sharing file/line/CWE;
- conservative scanner-aware exact matches when stronger evidence is unavailable.

The user sees one logical issue with multiple supporting sources instead of several copies of the same alert.

## Baselines

After a scan:

```bash
npm run synsec -- baseline .synsec/report.json
```

A later scan can compare against it:

```bash
npm run synsec -- scan . --baseline .synsec/baseline.json
```

The new report tracks new, fixed, and persisting findings. This makes SynSec useful as a regression detector rather than only a one-time scanner.

## Optional AI review

AI is a **second-pass reviewer**, not the source of truth. It is disabled by default.

SynSec supports endpoints implementing the OpenAI-compatible `/chat/completions` shape, including local gateways and model routers. A router such as OmniRoute, a self-hosted gateway, or another compatible provider can therefore sit behind SynSec without tying the project to one model vendor.

```bash
export SYNSEC_AI_BASE_URL="http://localhost:PORT/v1"
export SYNSEC_AI_MODEL="your/model-id"
export SYNSEC_AI_API_KEY="optional-key"

npm run synsec -- scan . --ai
```

By default the AI reviewer receives normalized finding metadata but **not repository source code**. To explicitly allow a small bounded source excerpt around a finding:

```bash
npm run synsec -- scan . --ai --ai-source
```

AI output is written separately to `.synsec/ai-review.json` so deterministic scanner evidence remains distinguishable from model inference.

The review uses seven checks:

1. Is there a concrete affected location?
2. Is untrusted input involved when required by the finding?
3. Is there a security-sensitive sink or invariant violation?
4. Is the path reachable rather than dead/example code?
5. Were relevant mitigations considered?
6. Is there actual scanner/code evidence?
7. Is there a specific remediation?

Unknown evidence stays `unknown`; the reviewer is instructed not to invent proof.

## Privacy and network behavior

Repository contents stay local to SynSec and its local scanner processes unless the operator explicitly enables an integration or scanner behavior that communicates externally.

Important exceptions to understand:

- OSV-Scanner normally queries vulnerability/package services for dependency metadata unless configured for its offline mode externally.
- Opengrep's `auto` rules configuration may fetch rule configuration from the network.
- OpenSSF Scorecard can use Git hosting APIs and may need a GitHub token for complete/rate-limit-friendly results.
- AI review sends normalized finding metadata to the configured model endpoint when enabled.
- Source excerpts are only sent to the AI endpoint when `sendSourceContext` or `--ai-source` is explicitly enabled.

Secret scanner output is requested with full redaction, and SynSec deliberately does not copy secret values into normalized findings.

## Architecture

```text
repository
   |
   +--> repository inventory
   |
   +--> scanner adapters
           |
           +-- Opengrep
           +-- Betterleaks / Gitleaks
           +-- OSV-Scanner
           +-- Trivy
           +-- Grype
           +-- Checkov
           +-- OpenSSF Scorecard
                  |
                  v
          normalized findings
                  |
                  v
        correlation / deduplication
                  |
          +-------+--------+
          |                |
          v                v
      reports          optional AI review
   JSON/HTML/SARIF       (separate evidence)
          |
          v
      baseline diff
```

The codebase is split into small packages:

```text
apps/cli              command-line product
packages/core         domain model + correlation
packages/config       stable configuration format
packages/scanner-sdk  scanner adapter/process boundary
packages/scanners     built-in scanner integrations
packages/repository   safe repository inventory/context
packages/report       JSON/SARIF/HTML + baselines
packages/engine       orchestration and failure isolation
packages/ai           opt-in provider-agnostic review gate
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for trust boundaries and package details and [`docs/ROADMAP.md`](docs/ROADMAP.md) for planned work.

## Safety model

SynSec's primary job is defensive analysis of repositories the operator owns or is authorized to assess. Repository scanning does not execute the target project's application or build scripts.

External attack-surface or bug-bounty functionality, if added later, will remain a separate explicitly authorized mode with scope controls rather than weakening the repository-first default.

## Development

```bash
npm install
npm run build
npm test
npm run typecheck
```

CI runs the build, typecheck, and test suite on Node 20 and Node 24.

## Project status

v0.2 is intended to be the first release worth hands-on testing. The next major work after scanner reliability is repository reachability/context, GitHub pull-request integration, stronger finding lifecycle management, reusable defensive workflows, and a richer persistent web application.

## License

A SynSec project license has not been selected yet. Third-party scanner engines retain their own licenses and are not vendored into SynSec.
