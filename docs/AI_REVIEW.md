# AI finding review and consensus

SynSec AI review is an optional advisory layer over deterministic repository scanner findings. It is disabled by default, does not create scanner evidence, does not authorize repository writes, and does not expand scanning to live external targets.

## Single-model review

Existing single-model CLI behavior remains available with `--ai-model <model>` or the configured/environment model. `synsec review` and `synsec scan --ai` write the existing schema-version-1 review artifact so current consumers do not receive a silent format change.

A model reviews one normalized finding against SynSec's seven-question evidence gate. Source context is omitted by default and can be enabled only when configuration plus the selected defensive workflow permit it. Secret findings cannot receive source excerpts at the AI provider boundary.

## Multi-model consensus

Use an explicit comma-separated model set to request independent reviews:

```text
synsec review .synsec/report.json \
  --ai-base-url <openai-compatible-base-url> \
  --ai-models reviewer-a,reviewer-b,reviewer-c \
  --ai-min-reviewers 2 \
  --ai-review-concurrency 2
```

`--ai-models` requires between two and ten unique model ids. It cannot be combined with `--ai-model`. `--ai-min-reviewers` must be between two and the selected model count. Review concurrency is bounded between one and four and can never exceed the model count. Invalid values fail instead of being silently clamped.

Each model receives the same bounded finding/context input independently. Provider failures are isolated and credential text is redacted from returned failure diagnostics. If fewer than the required number of distinct reviewers succeed, consensus is `insufficient` with an `uncertain` verdict rather than silently lowering the requirement.

Consensus requires an actual majority for a non-uncertain aggregate verdict. Ties or split reviewer outcomes remain `uncertain`. The output preserves individual reviews, provider failures, agreeing/dissenting model ids, gate vote counts, aggregate severity/confidence, and agreement status.

## Consensus output

Multi-model mode writes schema version 2 and is explicitly labeled:

```json
{
  "schemaVersion": 2,
  "reviewMode": "consensus",
  "models": ["reviewer-a", "reviewer-b", "reviewer-c"],
  "interpretation": "model-consensus-not-scanner-evidence",
  "reviews": {}
}
```

Each finding entry includes the independent model reviews plus the aggregate consensus. The aggregate itself repeats the `model-consensus-not-scanner-evidence` interpretation. Downstream lifecycle or remediation logic must not reinterpret a model majority as proof that a scanner finding is confirmed, exploitable, reachable, or fixed.

## Source and workflow boundaries

Workflow capability checks run before review. A workflow that prohibits source context continues to prohibit it regardless of how many models are selected. The multi-review orchestration layer separately refuses source context for secret findings even when a custom reviewer is injected.

The OpenAI-compatible endpoint is explicitly operator-configured AI infrastructure. Model review does not derive URLs from findings, source code, scanner output, webhook payloads, or repository metadata, and it is not used for autonomous external security assessment.

## Operational guidance

Use multiple reviewers when independent model disagreement is useful for human triage, not as a replacement for deterministic scanning or code review. For production use, keep API credentials outside repository files, bound model cost and concurrency, select workflows deliberately, and retain scanner/lifecycle evidence separately from AI artifacts.
