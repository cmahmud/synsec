import test from "node:test";
import assert from "node:assert/strict";
import {
  assertWorkflowCapabilitiesAllowed,
  assertWorkflowSourceContextAllowed,
  builtInWorkflows,
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

test("workflow capability checks reject undeclared access", () => {
  const workflow = getWorkflow("report-writing");
  assert.ok(workflow);
  assert.doesNotThrow(() => assertWorkflowCapabilitiesAllowed(workflow, ["read-normalized-findings", "read-lifecycle-state"]));
  assert.throws(
    () => assertWorkflowCapabilitiesAllowed(workflow, ["read-bounded-source-context", "propose-remediation"]),
    /read-bounded-source-context, propose-remediation/,
  );
});

test("fix verification workflow requires deterministic report and lifecycle evidence", () => {
  const workflow = getWorkflow("fix-verification");
  assert.ok(workflow);
  assert.equal(workflow.categories, "all");
  assert.equal(workflow.sourceContextAllowed, true);
  assert.ok(workflow.capabilities.includes("read-scan-reports"));
  assert.ok(workflow.capabilities.includes("read-lifecycle-state"));
  assert.match(workflow.reviewInstructions, /deterministic remediation verification/i);
  assert.match(workflow.reviewInstructions, /inconclusive/i);
});

test("report writing workflow cannot request source context", () => {
  const workflow = getWorkflow("report-writing");
  assert.ok(workflow);
  assert.equal(workflow.categories, "all");
  assert.equal(workflow.sourceContextAllowed, false);
  assert.ok(workflow.capabilities.includes("read-normalized-findings"));
  assert.ok(workflow.capabilities.includes("read-lifecycle-state"));
  assert.throws(
    () => assertWorkflowSourceContextAllowed(workflow, true),
    /does not permit source context/,
  );
});

test("all built-in workflows prohibit external network assessment and require approval for writes", () => {
  const workflows = builtInWorkflows();
  assert.ok(workflows.length >= 6);
  for (const workflow of workflows) {
    assert.equal(workflow.externalNetworkAssessment, "forbidden");
    assert.equal(workflow.repositoryWriteRequiresApproval, true);
  }
});
