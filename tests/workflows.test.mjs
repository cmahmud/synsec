import test from "node:test";
import assert from "node:assert/strict";
import {
  assertWorkflowSourceContextAllowed,
  getWorkflow,
  workflowFindings,
} from "../packages/workflows/dist/index.js";

const findings = [
  {
    fingerprint: "dep",
    primary: { id: "dep", title: "dependency", category: "dependency", severity: "high", confidence: 1, scanner: { name: "fixture" } },
    duplicates: [],
    sources: [{ name: "fixture" }],
  },
  {
    fingerprint: "secret",
    primary: { id: "secret", title: "secret", category: "secret", severity: "high", confidence: 1, scanner: { name: "fixture" } },
    duplicates: [],
    sources: [{ name: "fixture" }],
  },
  {
    fingerprint: "iac",
    primary: { id: "iac", title: "iac", category: "iac", severity: "medium", confidence: 1, scanner: { name: "fixture" } },
    duplicates: [],
    sources: [{ name: "fixture" }],
  },
];

test("dependency workflow selects dependency-family findings", () => {
  const workflow = getWorkflow("dependency-review");
  assert.ok(workflow);
  const selected = workflowFindings(findings, workflow);
  assert.deepEqual(selected.map((finding) => finding.fingerprint), ["dep"]);
});

test("secrets workflow prohibits source-context transmission", () => {
  const workflow = getWorkflow("secrets-review");
  assert.ok(workflow);
  assert.equal(workflow.sourceContextAllowed, false);
  assert.throws(
    () => assertWorkflowSourceContextAllowed(workflow, true),
    /does not permit source context/,
  );
  assert.doesNotThrow(() => assertWorkflowSourceContextAllowed(workflow, false));
});

test("all built-in workflows prohibit external network assessment", () => {
  for (const id of ["repository-review", "dependency-review", "secrets-review", "infrastructure-review"]) {
    const workflow = getWorkflow(id);
    assert.ok(workflow);
    assert.equal(workflow.externalNetworkAssessment, "forbidden");
    assert.equal(workflow.repositoryWriteRequiresApproval, true);
  }
});
