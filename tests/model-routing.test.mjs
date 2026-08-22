import test from "node:test";
import assert from "node:assert/strict";
import { routeModel, routeModelSet } from "../packages/workflows/dist/routing.js";

const candidates = [
  {
    id: "local-small",
    tasks: ["fast-classifier", "report-writer"],
    costTier: 0,
    latencyTier: 1,
    privacy: "local",
    supportsSourceContext: true,
  },
  {
    id: "remote-security",
    tasks: ["security-reasoner", "code-reasoner", "verifier"],
    costTier: 2,
    latencyTier: 2,
    privacy: "remote",
    supportsSourceContext: true,
  },
  {
    id: "private-security",
    tasks: ["security-reasoner", "verifier"],
    costTier: 1,
    latencyTier: 3,
    privacy: "private-remote",
    supportsSourceContext: false,
  },
];

test("routing chooses the lowest-cost eligible model by task", () => {
  const decision = routeModel(candidates, {
    task: "security-reasoner",
    sourceContextRequested: false,
  });
  assert.equal(decision.candidate.id, "private-security");
  assert.ok(decision.reason.some((reason) => /cost tier 1/.test(reason)));
});

test("source-context routing excludes models that cannot receive source", () => {
  const decision = routeModel(candidates, {
    task: "security-reasoner",
    sourceContextRequested: true,
  });
  assert.equal(decision.candidate.id, "remote-security");
  assert.ok(decision.reason.includes("permits source context"));
});

test("routing enforces cost and local-only constraints rather than silently widening policy", () => {
  assert.throws(
    () => routeModel(candidates, {
      task: "security-reasoner",
      sourceContextRequested: false,
      maxCostTier: 0,
    }),
    /No model candidate satisfies routing constraints/,
  );
  assert.throws(
    () => routeModel(candidates, {
      task: "verifier",
      sourceContextRequested: false,
      requireLocal: true,
    }),
    /privacy=local-only/,
  );
});

test("local preference is deterministic when multiple candidates remain eligible", () => {
  const expanded = [
    ...candidates,
    {
      id: "remote-cheap-writer",
      tasks: ["report-writer"],
      costTier: 0,
      latencyTier: 0,
      privacy: "remote",
      supportsSourceContext: false,
    },
  ];
  const defaultDecision = routeModel(expanded, {
    task: "report-writer",
    sourceContextRequested: false,
  });
  assert.equal(defaultDecision.candidate.id, "remote-cheap-writer");

  const privateDecision = routeModel(expanded, {
    task: "report-writer",
    sourceContextRequested: false,
    preferLocal: true,
  });
  assert.equal(privateDecision.candidate.id, "local-small");
});

test("routeModelSet selects distinct reviewers with the same eligibility policy", () => {
  const expanded = [
    ...candidates,
    {
      id: "local-security",
      tasks: ["security-reasoner", "verifier"],
      costTier: 1,
      latencyTier: 1,
      privacy: "local",
      supportsSourceContext: true,
    },
    {
      id: "remote-security-2",
      tasks: ["security-reasoner"],
      costTier: 2,
      latencyTier: 1,
      privacy: "remote",
      supportsSourceContext: true,
    },
    {
      id: "local-security",
      tasks: ["security-reasoner"],
      costTier: 0,
      latencyTier: 0,
      privacy: "local",
      supportsSourceContext: true,
    },
  ];
  const decision = routeModelSet(expanded, {
    task: "security-reasoner",
    sourceContextRequested: false,
    preferLocal: true,
  }, 3);
  assert.deepEqual(decision.candidates.map((candidate) => candidate.id), [
    "local-security",
    "private-security",
    "remote-security-2",
  ]);
  assert.equal(new Set(decision.candidates.map((candidate) => candidate.id)).size, 3);
});

test("routeModelSet fails closed when source/privacy constraints leave too few reviewers", () => {
  assert.throws(
    () => routeModelSet(candidates, {
      task: "security-reasoner",
      sourceContextRequested: true,
    }, 2),
    /Only 1 distinct model candidate\(s\).*2 required/,
  );
  assert.throws(
    () => routeModelSet(candidates, {
      task: "verifier",
      sourceContextRequested: false,
      requireLocal: true,
    }, 2),
    /Only 0 distinct model candidate\(s\).*privacy=local-only/,
  );
});

test("routeModelSet validates the consensus reviewer count", () => {
  assert.throws(
    () => routeModelSet(candidates, { task: "security-reasoner", sourceContextRequested: false }, 1),
    /between 2 and 10/,
  );
});
