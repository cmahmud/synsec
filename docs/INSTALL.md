# Installing SynSec and scanner engines

SynSec itself is a Node.js application. Detection engines remain separate binaries so they can be upgraded independently and keep their original licenses.

You do **not** need every engine installed to use SynSec. `synsec doctor` shows what is available and scans continue with the engines that are present.

## SynSec

```bash
git clone https://github.com/cmahmud/synsec.git
cd synsec
npm install
npm run build
npm run synsec -- doctor .
```

Node.js 20+ is supported. Node.js 24 is recommended.

## Opengrep

Project: https://github.com/opengrep/opengrep

Linux/macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/opengrep/opengrep/main/install.ps1 | iex
```

Confirm:

```bash
opengrep --version
```

## Betterleaks

Project: https://github.com/betterleaks/betterleaks

Betterleaks is SynSec's preferred secrets engine for new installs. It is maintained by the team behind Gitleaks.

macOS:

```bash
brew install betterleaks
```

With Go:

```bash
go install github.com/betterleaks/betterleaks@latest
```

Or use a release binary from the project's GitHub Releases page.

SynSec runs Betterleaks with fully redacted report output. Live credential validation is not enabled by the SynSec adapter.

## Gitleaks (optional fallback)

Project: https://github.com/gitleaks/gitleaks

SynSec keeps a Gitleaks adapter for environments that already have it installed, but it is not in the default scanner list.

## OSV-Scanner

Project: https://github.com/google/osv-scanner

With Go:

```bash
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
```

Prebuilt release binaries are also available from GitHub Releases.

Confirm:

```bash
osv-scanner --version
```

## Trivy

Project: https://github.com/aquasecurity/trivy

Use the installation method documented by Aqua for your operating system. Trivy is available through common package managers and as a standalone binary.

Confirm:

```bash
trivy --version
```

## Grype

Project: https://github.com/anchore/grype

Linux/macOS installation helper published by Anchore:

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b "$HOME/.local/bin"
```

Confirm:

```bash
gripe_version=$(grype version 2>/dev/null || true)
printf '%s\n' "$gripe_version"
```

## Checkov

Project: https://github.com/bridgecrewio/checkov

`pipx` is recommended so Checkov does not modify the system Python environment:

```bash
pipx install checkov
```

Confirm:

```bash
checkov --version
```

## Verify the full setup

From the SynSec repository:

```bash
npm run synsec -- doctor .
```

A healthy setup can look like:

```text
OK        Opengrep           ...
OK        Betterleaks        ...
DISABLED  Gitleaks           ...
OK        OSV-Scanner        ...
OK        Trivy              ...
OK        Grype              ...
OK        Checkov            ...
```

Missing scanners are not fatal unless your own CI policy requires them. SynSec reports unavailable selected engines so a scan cannot silently pretend that coverage existed.

## Network/privacy notes

Some engines use network services for rule or vulnerability metadata. See the main README for the current privacy model. AI review is separately opt-in, and source excerpts are not sent to a model endpoint unless explicitly enabled.
