import assert from "node:assert/strict";
import test from "node:test";
import { resolveAiReviewSelection } from "../apps/cli/dist/ai-options.js";

const base = { baseUrl: "https://ai.example.invalid/v1" };

test("AI review selection preserves existing single-model behavior", () => {
  const selection = resolveAiReviewSelection({
    ...base,
    configuredModel: "reviewer-a",
    apiKey: "secret-key",
  });
  assert.equal(selection.mode, "single");
  assert.deepEqual(selection.models, ["reviewer-a"]);
  assert.equal(selection.minimumReviewers, 1);
  assert.equal(selection.concurrency, 1);
  assert.equal(selection.providers[0].apiKey, "secret-key");
});

test("AI review selection supports bounded deduplicated consensus models", () => {
  const selection = resolveAiReviewSelection({
    ...base,
    multipleModels: " reviewer-a,reviewer-b,reviewer-a,reviewer-c ",
    minimumReviewers: 3,
    concurrency: 2,
  });
  assert.equal(selection.mode, "consensus");
  assert.deepEqual(selection.models, ["reviewer-a", "reviewer-b", "reviewer-c"]);
  assert.equal(selection.minimumReviewers, 3);
  assert.equal(selection.concurrency, 2);
  assert.deepEqual(selection.providers.map((provider) => provider.model), selection.models);
});

test("AI review selection rejects ambiguous or insufficient model input", () => {
  assert.throws(() => resolveAiReviewSelection({
    ...base,
    singleModel: "a",
    multipleModels: "b,c",
  }), /either --ai-model or --ai-models/);
  assert.throws(() => resolveAiReviewSelection({ ...base, multipleModels: "same,same" }), /at least two unique/);
  assert.throws(() => resolveAiReviewSelection({ ...base }), /no model is configured/);
});

test("AI review selection rejects excessive models and invalid consensus controls", () => {
  assert.throws(() => resolveAiReviewSelection({
    ...base,
    multipleModels: Array.from({ length: 11 }, (_, index) => `m${index}`).join(","),
  }), /at most 10/);
  assert.throws(() => resolveAiReviewSelection({
    ...base,
    multipleModels: "a,b",
    minimumReviewers: 3,
  }), /--ai-min-reviewers/);
  assert.throws(() => resolveAiReviewSelection({
    ...base,
    multipleModels: "a,b,c,d,e",
    concurrency: 5,
  }), /--ai-review-concurrency/);
});
