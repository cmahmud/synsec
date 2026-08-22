# Reusable defensive workflows

SynSec's model-facing layer should be built from small workflows with explicit inputs and capabilities rather than one enormous prompt that implicitly has access to everything.

This idea is useful for two reasons:

1. scanner orchestration and model reasoning become independently replaceable;
2. each workflow can declare exactly which repository evidence and actions it is allowed to use.

The workflow system is not implemented in v0.2 yet. This document defines the direction so future agent work has a stable boundary.

## Proposed workflow contract

A workflow should eventually declare something equivalent to:

```yaml
id: dependency-review
version: 1
inputs:
  - correlated-findings
  - dependency-metadata
capabilities:
  - read-normalized-findings
  - read-bounded-source-context
model:
  task: security-review
output:
  schema: finding-review-v1
approval:
  repository-write: required
  external-network-assessment: forbidden
```

The important part is not YAML specifically. The important part is that capabilities are explicit and machine-enforced.

## Initial workflow set

### Repository review

Inputs:

- normalized findings;
- repository language/framework inventory;
- selected bounded source context.

Output:

- evidence-based finding review;
- confidence and severity recommendation;
- unresolved questions.

### Dependency review

Inputs:

- OSV/Trivy/Grype findings;
- package identity and installed/fixed versions;
- scanner-provided reachability information when available.

Output:

- deduplicated advisory explanation;
- fix availability;
- whether evidence suggests the vulnerable package is actually relevant to the project.

### Secrets review

Inputs:

- **redacted** secret findings only;
- file and line metadata;
- Git-history metadata where safe.

Output:

- rotation/removal guidance;
- repository-history cleanup recommendation;
- confidence assessment.

A model must never need the secret value itself for this workflow.

### Infrastructure review

Inputs:

- Checkov/Trivy IaC findings;
- the affected configuration excerpt;
- repository deployment metadata.

Output:

- configuration-risk explanation;
- defensive remediation;
- uncertainty when deployment context is missing.

### Fix verification

Inputs:

- previous finding;
- proposed/current code change;
- rescan result;
- relevant tests.

Output:

- fixed / partially fixed / still present / unable to verify.

The deterministic rescan remains authoritative. Model review explains evidence rather than declaring a vulnerability fixed on its own.

### Report writing

Inputs:

- normalized/correlated finding;
- deterministic evidence;
- optional reviewed context.

Output:

- concise developer-facing explanation;
- remediation summary;
- references to scanner evidence and source locations.

## Seven-question evidence gate

The v0.2 AI reviewer already implements the first common workflow primitive. Every contextual finding review asks:

1. Is there a concrete affected location?
2. Is untrusted input involved when the finding requires it?
3. Is there a security-sensitive sink or invariant violation?
4. Is the affected path actually reachable rather than dead/example code?
5. Were relevant mitigations considered?
6. Is there scanner or code evidence supporting the conclusion?
7. Is there a specific, proportionate remediation?

An unanswered question stays `unknown`. A model should not fill gaps with invented evidence.

## Model routing

Workflows should request a capability class rather than hard-code one vendor/model name. Examples:

```text
fast-classifier
security-reasoner
code-reasoner
report-writer
verifier
```

A router can then map each task to an available model based on cost, latency, privacy, and capability. This keeps SynSec usable with cloud models, local models, or a mixed deployment.

## Human approval boundaries

A workflow may recommend a repository change, but v0.2 does not autonomously modify repositories.

Future write-capable workflows should require explicit approval before:

- editing source files;
- changing dependencies;
- creating a commit;
- opening a pull request;
- changing CI or infrastructure configuration.

External network assessment is a separate authorization domain. A future external-assessment mode must have its own explicit scope controls and must not inherit permission merely because a repository workflow can read code.

## Auditability

Every future workflow run should preserve:

- workflow ID and version;
- model/provider identifier;
- deterministic evidence references;
- whether source context was sent;
- output schema version;
- approval events;
- generated patch hash if a patch is produced.

This makes it possible to reproduce why SynSec reached a recommendation even when models or routing policies change later.
