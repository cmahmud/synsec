import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseUserWorkflow, readUserWorkflow } from "../packages/workflows/dist/user-defined.js";

const validWorkflow = {
  id: "custom-dependency-review",
  version: 1,
  displayName: "Custom Dependency Review",
  description: "Review dependency evidence for this repository.",
  reviewInstructions: "Prefer deterministic package and import evidence. Preserve uncertainty.",
  categories: ["dependency"],
  capabilities: ["read-normalized-findings", "read-dependency-metadata", "propose-remediation"],
  sourceContextAllowed: false,
  repositoryWriteRequiresApproval: true,
  externalNetworkAssessment: "forbidden",
};

test("user-defined workflow parser accepts capability-scoped defensive workflows", () => {
  const workflow = parseUserWorkflow(validWorkflow);
  assert.equal(workflow.id, "custom-dependency-review");
  assert.deepEqual(workflow.categories, ["dependency"]);
  assert.deepEqual(workflow.capabilities, [
    "read-normalized-findings",
    "read-dependency-metadata",
    "propose-remediation",
  ]);
  assert.equal(workflow.repositoryWriteRequiresApproval, true);
  assert.equal(workflow.externalNetworkAssessment, "forbidden");
});

test("user-defined workflows cannot weaken repository safety boundaries", () => {
  assert.throws(
    () => parseUserWorkflow({ ...validWorkflow, repositoryWriteRequiresApproval: false }),
    /must require approval/,
  );
  assert.throws(
    () => parseUserWorkflow({ ...validWorkflow, externalNetworkAssessment: "allowed" }),
    /must forbid external network assessment/,
  );
  assert.throws(
    () => parseUserWorkflow({ ...validWorkflow, capabilities: ["read-normalized-findings", "execute-shell"] }),
    /Unsupported workflow capability/,
  );
});

test("source context requires an explicit bounded-source capability", () => {
  assert.throws(
    () => parseUserWorkflow({ ...validWorkflow, sourceContextAllowed: true }),
    /read-bounded-source-context/,
  );
  const workflow = parseUserWorkflow({
    ...validWorkflow,
    sourceContextAllowed: true,
    capabilities: ["read-normalized-findings", "read-bounded-source-context"],
  });
  assert.equal(workflow.sourceContextAllowed, true);
});

test("user-defined workflow files are bounded and parsed from JSON", async () => {
  const root = await mkdtemp(join(tmpdir(), "synsec-workflow-test-"));
  try {
    const path = join(root, "workflow.json");
    await writeFile(path, `${JSON.stringify(validWorkflow, null, 2)}\n`);
    const workflow = await readUserWorkflow(path);
    assert.equal(workflow.displayName, "Custom Dependency Review");

    await writeFile(path, "{");
    await assert.rejects(() => readUserWorkflow(path), /not valid JSON/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
