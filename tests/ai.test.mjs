import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { reviewFinding } from "../packages/ai/dist/index.js";

test("AI review uses the OpenAI-compatible boundary and normalizes the seven-question gate", async () => {
  let observedBody = "";
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      observedBody = body;
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({
        choices: [{
          message: {
            content: JSON.stringify({
              verdict: "likely",
              confidence: 0.88,
              severity: "high",
              summary: "Evidence supports the scanner finding",
              rationale: "The provided evidence is concrete but reachability is not fully established.",
              gate: [
                { id: "concrete", answer: "yes", note: "A source location is present." },
                { id: "evidence", answer: "yes", note: "Scanner evidence is present." },
              ],
              remediation: "Use the safer API described by the scanner.",
            }),
          },
        }],
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const review = await reviewFinding({
      id: "fixture",
      title: "Fixture finding",
      category: "sast",
      severity: "high",
      confidence: 0.9,
      scanner: { name: "fixture", ruleId: "FIXTURE-1" },
      location: { path: "src/app.ts", startLine: 5 },
    }, {
      baseUrl: `http://127.0.0.1:${address.port}/v1`,
      model: "fixture-model",
      apiKey: "test-key",
    });

    assert.equal(review.verdict, "likely");
    assert.equal(review.model, "fixture-model");
    assert.equal(review.gate.length, 7);
    assert.equal(review.gate.find((item) => item.id === "concrete")?.answer, "yes");
    assert.equal(review.gate.find((item) => item.id === "reachable")?.answer, "unknown");
    assert.match(observedBody, /fixture-model/);
    assert.match(observedBody, /No source excerpt was provided/);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
