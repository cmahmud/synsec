import test from "node:test";
import assert from "node:assert/strict";

import { buildReviewConsensus } from "../packages/ai/dist/consensus.js";

function review(model, verdict, confidence, severity = "high", gateAnswer = "yes") {
  return {
    model,
    verdict,
    confidence,
    severity,
    summary: `${model} summary`,
    rationale: `${model} rationale`,
    gate: [
      { id: "concrete", question: "Concrete?", answer: gateAnswer, note: "evidence" },
      { id: "reachable", question: "Reachable?", answer: "unknown", note: "unknown" },
    ],
  };
}

test("buildReviewConsensus returns a majority verdict without treating it as scanner evidence", () => {
  const consensus = buildReviewConsensus([
    review("model-a", "confirmed", 0.9, "high"),
    review("model-b", "confirmed", 0.7, "medium"),
    review("model-c", "uncertain", 0.6, "critical", "unknown"),
  ]);

  assert.equal(consensus.verdict, "confirmed");
  assert.equal(consensus.agreement, "majority");
  assert.equal(consensus.severity, "critical");
  assert.equal(consensus.confidence, 0.8);
  assert.deepEqual(consensus.agreeingModels, ["model-a", "model-b"]);
  assert.deepEqual(consensus.dissentingModels, ["model-c"]);
  assert.equal(consensus.interpretation, "model-consensus-not-scanner-evidence");
  assert.deepEqual(consensus.gate[0], {
    id: "concrete",
    question: "Concrete?",
    answer: "yes",
    yes: 2,
    no: 0,
    unknown: 1,
  });
});

test("split reviewer verdicts fail closed to uncertain", () => {
  const consensus = buildReviewConsensus([
    review("model-a", "confirmed", 0.9),
    review("model-b", "false-positive", 0.9, "low", "no"),
  ]);
  assert.equal(consensus.verdict, "uncertain");
  assert.equal(consensus.agreement, "split");
  assert.deepEqual(consensus.agreeingModels, []);
  assert.deepEqual(consensus.dissentingModels, ["model-a", "model-b"]);
  assert.equal(consensus.gate[0].answer, "unknown");
});

test("insufficient unique reviewers never fabricate consensus", () => {
  const consensus = buildReviewConsensus([
    review("same-model", "confirmed", 0.95),
    review("same-model", "confirmed", 0.95),
  ]);
  assert.equal(consensus.verdict, "uncertain");
  assert.equal(consensus.severity, "unknown");
  assert.equal(consensus.confidence, 0);
  assert.equal(consensus.agreement, "insufficient");
  assert.equal(consensus.reviewerCount, 1);
});

test("unanimous false-positive consensus preserves the reviewers' bounded severity", () => {
  const consensus = buildReviewConsensus([
    review("model-a", "false-positive", 0.8, "low", "no"),
    review("model-b", "false-positive", 0.6, "info", "no"),
  ]);
  assert.equal(consensus.verdict, "false-positive");
  assert.equal(consensus.agreement, "unanimous");
  assert.equal(consensus.severity, "low");
  assert.equal(consensus.confidence, 0.7);
});
