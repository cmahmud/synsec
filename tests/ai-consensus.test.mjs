import test from "node:test";
import assert from "node:assert/strict";

import { buildReviewConsensus, reviewFindingWithConsensus } from "../packages/ai/dist/consensus.js";

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

const finding = {
  id: "f-1",
  title: "Unsafe input",
  description: "Untrusted input reaches a sensitive operation.",
  category: "sast",
  severity: "high",
  confidence: 0.9,
  scanner: { name: "opengrep", ruleId: "unsafe-input" },
  location: { path: "src/app.ts", startLine: 10, endLine: 10 },
};

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

test("reviewFindingWithConsensus bounds independent reviewer execution and isolates failures", async () => {
  let active = 0;
  let maximumActive = 0;
  const reviewer = async (_finding, provider) => {
    active += 1;
    maximumActive = Math.max(maximumActive, active);
    await new Promise((resolve) => setTimeout(resolve, 5));
    active -= 1;
    if (provider.model === "model-c") throw new Error(`provider failed with ${provider.apiKey}`);
    return review(provider.model, "confirmed", provider.model === "model-a" ? 0.9 : 0.7);
  };

  const result = await reviewFindingWithConsensus(finding, [
    { baseUrl: "https://models.invalid", model: "model-a", apiKey: "secret-a" },
    { baseUrl: "https://models.invalid", model: "model-b", apiKey: "secret-b" },
    { baseUrl: "https://models.invalid", model: "model-c", apiKey: "secret-c" },
    { baseUrl: "https://models.invalid", model: "model-a", apiKey: "duplicate" },
  ], undefined, undefined, { concurrency: 2, reviewer });

  assert.equal(maximumActive <= 2, true);
  assert.deepEqual(result.reviews.map((item) => item.model), ["model-a", "model-b"]);
  assert.equal(result.consensus.agreement, "unanimous");
  assert.equal(result.consensus.verdict, "confirmed");
  assert.equal(result.failures.length, 1);
  assert.equal(result.failures[0].model, "model-c");
  assert.equal(result.failures[0].message.includes("secret-c"), false);
  assert.match(result.failures[0].message, /\[REDACTED\]/);
});

test("reviewFindingWithConsensus fails closed when successful reviewers are below the minimum", async () => {
  const result = await reviewFindingWithConsensus(finding, [
    { baseUrl: "https://models.invalid", model: "model-a" },
    { baseUrl: "https://models.invalid", model: "model-b" },
  ], undefined, undefined, {
    minimumReviewers: 2,
    reviewer: async (_finding, provider) => {
      if (provider.model === "model-b") throw new Error("unavailable");
      return review(provider.model, "confirmed", 0.9);
    },
  });
  assert.equal(result.consensus.agreement, "insufficient");
  assert.equal(result.consensus.verdict, "uncertain");
});

test("multi-review boundary prohibits source context for secret findings before reviewer execution", async () => {
  let called = false;
  await assert.rejects(
    () => reviewFindingWithConsensus(
      { ...finding, category: "secret" },
      [{ baseUrl: "https://models.invalid", model: "model-a" }, { baseUrl: "https://models.invalid", model: "model-b" }],
      { path: "src/app.ts", startLine: 1, endLine: 1, excerpt: "secret material" },
      undefined,
      { reviewer: async () => { called = true; return review("model-a", "confirmed", 0.9); } },
    ),
    /Source context is prohibited for secret findings/,
  );
  assert.equal(called, false);
});
