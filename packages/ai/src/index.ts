import type { Finding } from "@synsec/core";
import type { FindingContext } from "@synsec/repository";

export type ReviewAnswer = "yes" | "no" | "unknown";

export interface ReviewGateQuestion {
  id: string;
  question: string;
  answer: ReviewAnswer;
  note: string;
}

export interface AiFindingReview {
  verdict: "confirmed" | "likely" | "uncertain" | "false-positive";
  confidence: number;
  severity: Finding["severity"];
  summary: string;
  rationale: string;
  gate: ReviewGateQuestion[];
  remediation?: string;
  model: string;
}

export interface OpenAiCompatibleConfig {
  baseUrl: string;
  apiKey?: string;
  model: string;
  timeoutMs?: number;
}

interface ChatCompletionResponse {
  choices?: Array<{
    message?: {
      content?: string;
    };
  }>;
}

const gateQuestions = [
  ["concrete", "Is there a concrete vulnerable code or configuration location?"],
  ["input", "Is attacker-controlled or otherwise untrusted input involved where the finding requires it?"],
  ["sink", "Does the code reach a security-sensitive sink or violate a meaningful security invariant?"],
  ["reachable", "Is the affected path reachable in the repository's actual application flow rather than dead/example code?"],
  ["mitigations", "Have relevant validations, escaping, authorization checks, sandboxing, or other mitigations been accounted for?"],
  ["evidence", "Is there scanner or code evidence supporting the conclusion without relying only on speculation?"],
  ["actionable", "Is there a specific, proportionate remediation that addresses the underlying issue?"],
] as const;

function stripCodeFence(value: string): string {
  const trimmed = value.trim();
  const match = /^```(?:json)?\s*([\s\S]*?)\s*```$/i.exec(trimmed);
  return match?.[1] ?? trimmed;
}

function clampConfidence(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return 0.5;
  return Math.max(0, Math.min(1, value));
}

function isSeverity(value: unknown): value is Finding["severity"] {
  return value === "critical" || value === "high" || value === "medium" || value === "low" || value === "info" || value === "unknown";
}

function answer(value: unknown): ReviewAnswer {
  return value === "yes" || value === "no" || value === "unknown" ? value : "unknown";
}

function verdict(value: unknown): AiFindingReview["verdict"] {
  return value === "confirmed" || value === "likely" || value === "uncertain" || value === "false-positive"
    ? value
    : "uncertain";
}

function normalizeReview(value: unknown, finding: Finding, model: string): AiFindingReview {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("AI review response was not a JSON object.");
  }
  const record = value as Record<string, unknown>;
  const rawGate = Array.isArray(record.gate) ? record.gate : [];
  const gate = gateQuestions.map(([id, question]) => {
    const found = rawGate.find((item) => typeof item === "object" && item !== null && (item as Record<string, unknown>).id === id) as Record<string, unknown> | undefined;
    return {
      id,
      question,
      answer: answer(found?.answer),
      note: typeof found?.note === "string" ? found.note : "No model note provided.",
    };
  });

  const review: AiFindingReview = {
    verdict: verdict(record.verdict),
    confidence: clampConfidence(record.confidence),
    severity: isSeverity(record.severity) ? record.severity : finding.severity,
    summary: typeof record.summary === "string" ? record.summary : finding.title,
    rationale: typeof record.rationale === "string" ? record.rationale : "No rationale provided.",
    gate,
    model,
  };
  if (typeof record.remediation === "string") review.remediation = record.remediation;
  return review;
}

function safeMetadataForModel(finding: Finding): Record<string, unknown> | undefined {
  if (!finding.metadata) return undefined;
  if (finding.category !== "secret") return finding.metadata;

  // Keep the model boundary resilient even if a future secret-scanner adapter
  // accidentally adds richer metadata. Only a deliberately narrow allowlist
  // can cross the boundary for secret findings.
  const allowed = new Set([
    "validationStatus",
    "validationReason",
    "commit",
    "author",
    "date",
    "tags",
  ]);
  const safe: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(finding.metadata)) {
    if (allowed.has(key)) safe[key] = value;
  }
  return safe;
}

function buildPrompt(finding: Finding, context?: FindingContext, reviewInstructions?: string): string {
  const safeFinding = {
    title: finding.title,
    description: finding.description,
    category: finding.category,
    severity: finding.severity,
    confidence: finding.confidence,
    scanner: finding.scanner,
    location: finding.location,
    identifiers: finding.identifiers,
    remediation: finding.remediation,
    metadata: safeMetadataForModel(finding),
  };

  const contextBlock = context
    ? `\nRepository excerpt (${context.path}, lines ${context.startLine}-${context.endLine}):\n${context.excerpt}`
    : "\nNo source excerpt was provided. Treat reachability and code-flow claims as unknown unless scanner evidence is sufficient.";
  const workflowBlock = reviewInstructions
    ? `\nWorkflow-specific review instructions:\n${reviewInstructions}\n`
    : "";

  return `You are reviewing a repository security scanner finding for defensive software assurance. Do not invent exploit steps, credentials, or evidence. Separate deterministic scanner evidence from inference. If the available context cannot answer a question, answer unknown. Return JSON only.${workflowBlock}\nFinding:\n${JSON.stringify(safeFinding, null, 2)}${contextBlock}\n\nAssess these seven gates:\n${gateQuestions.map(([id, question], index) => `${index + 1}. ${id}: ${question}`).join("\n")}\n\nReturn exactly this shape:\n{\n  "verdict": "confirmed|likely|uncertain|false-positive",\n  "confidence": 0.0,\n  "severity": "critical|high|medium|low|info|unknown",\n  "summary": "short summary",\n  "rationale": "brief evidence-grounded rationale",\n  "gate": [{"id":"concrete","answer":"yes|no|unknown","note":"brief note"}],\n  "remediation": "brief defensive remediation"\n}`;
}

export async function reviewFinding(
  finding: Finding,
  config: OpenAiCompatibleConfig,
  context?: FindingContext,
  reviewInstructions?: string,
): Promise<AiFindingReview> {
  if (finding.category === "secret" && context) {
    throw new Error("Source context is prohibited for secret findings at the AI provider boundary.");
  }

  const baseUrl = config.baseUrl.replace(/\/$/, "");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.timeoutMs ?? 90_000);

  try {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (config.apiKey) headers.authorization = `Bearer ${config.apiKey}`;

    const response = await fetch(`${baseUrl}/chat/completions`, {
      method: "POST",
      headers,
      signal: controller.signal,
      body: JSON.stringify({
        model: config.model,
        temperature: 0,
        messages: [
          {
            role: "system",
            content: "Perform concise defensive repository vulnerability triage. Return valid JSON only.",
          },
          { role: "user", content: buildPrompt(finding, context, reviewInstructions) },
        ],
      }),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`AI provider returned HTTP ${response.status}: ${text.slice(0, 500)}`);
    }

    const payload = (await response.json()) as ChatCompletionResponse;
    const content = payload.choices?.[0]?.message?.content;
    if (!content) throw new Error("AI provider returned no message content.");
    const parsed = JSON.parse(stripCodeFence(content)) as unknown;
    return normalizeReview(parsed, finding, config.model);
  } finally {
    clearTimeout(timeout);
  }
}
