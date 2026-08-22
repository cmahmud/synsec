# Reusable defensive workflows

SynSec's model-facing layer is built from small workflows with explicit inputs and capabilities rather than one enormous prompt that implicitly has access to everything.

This matters for two reasons:

1. scanner orchestration and model reasoning remain independently replaceable;
2. each workflow declares exactly which repository evidence and actions it is allowed to use.

The built-in workflow registry is implemented in `@synsec/workflows`. The definitions are intentionally small and machine-readable so future routing, UI, and hosted execution can enforce the same boundaries.

## Workflow contract

Each built-in workflow declares:

- a stable ID and version;
- the finding categories it accepts;
- explicit read/proposal capabilities;
- whether bounded source context is allowed;
- mandatory human approval for repository writes;
- an explicit prohibition on external network assessment.

The important part is that capabilities are explicit and machine-enforced rather than implied by a prompt.

## Built-in workflow set

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
- safe repository metadata.

Output:

- rotation/removal guidance;
- repository-history cleanup recommendation;
- confidence assessment.

Source context is prohibited for this workflow. A model never needs the secret value itself.

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

- previous and current normalized scan reports;
- deterministic remediation-verification result;
- lifecycle state;
- optional bounded source context;
- relevant tests when available.

Output:

- fixed / persisting / inconclusive / missing-baseline interpretation;
- explanation of scanner and scope coverage;
- suggested regression/security tests.

The deterministic rescan remains authoritative. A finding that disappears is only treated as fixed when a detecting scanner reran over the affected scope. Model review can explain the evidence but cannot override missing coverage.

### Report writing

Inputs:

- normalized/correlated findings;
- deterministic scan evidence;
- lifecycle state.

Output:

- concise developer-facing explanation;
- remediation summary;
- references to scanner evidence and source locations;
- explicit uncertainty when evidence is incomplete.

Source context is disabled for this workflow by design. The report writer summarizes normalized evidence rather than receiving arbitrary repository code or secret material.

## Seven-question evidence gate

The AI reviewer implements a common workflow primitive. Every contextual finding review asks:

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

A router can map each task to an available model based on cost, latency, privacy, and capability. This keeps SynSec usable with cloud models, local models, or a mixed deployment.

## Human approval boundaries

A workflow may recommend a repository change, but it does not autonomously modify repositories.

Any future write-capable workflow must require explicit approval before:

- editing source files;
- changing dependencies;
- creating a commit;
- opening a pull request;
- changing CI or infrastructure configuration.

External network assessment is a separate authorization domain. A future external-assessment mode must have its own explicit scope controls and must not inherit permission merely because a repository workflow can read code.

## Auditability

Every future persisted workflow run should preserve:

- workflow ID and version;
- model/provider identifier when a model is used;
- deterministic evidence references;
- whether source context was sent;
- output schema version;
- approval events;
- generated patch hash if a patch is produced.

This makes it possible to reproduce why SynSec reached a recommendation even when models or routing policies change later.
