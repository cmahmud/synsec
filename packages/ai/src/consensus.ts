import type { Finding, Severity } from "@synsec/core";
import type { FindingContext } from "@synsec/repository";
import {
  reviewFinding,
  type AiFindingReview,
  type OpenAiCompatibleConfig,
  type ReviewAnswer,
} from "./index.js";

export type ReviewConsensusAgreement = "unanimous" | "majority" | "split" | "insufficient";

export interface ReviewConsensusGate {
  id: string;
  question: string;
  answer: ReviewAnswer;
  yes: number;
  no: number;
  unknown: number;
}

export interface AiReviewConsensus {
  schemaVersion: 1;
  verdict: AiFindingReview["verdict"];
  severity: Severity;
  confidence: number;
  agreement: ReviewConsensusAgreement;
  reviewerCount: number;
  models: string[];
  agreeingModels: string[];
  dissentingModels: string[];
  gate: ReviewConsensusGate[];
  /** Consensus aggregates model inference; deterministic scanner evidence remains authoritative. */
  interpretation: "model-consensus-not-scanner-evidence";
}

export interface ReviewConsensusFailure {
  model: string;
  message: string;
}

export interface MultiReviewConsensusResult {
  reviews: AiFindingReview[];
  failures: ReviewConsensusFailure[];
  consensus: AiReviewConsensus;
}

export interface MultiReviewOptions {
  minimumReviewers?: number;
  concurrency?: number;
  reviewer?: typeof reviewFinding;
}

const severityRank: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  unknown: 0,
};

const verdictRank: Record<AiFindingReview["verdict"], number> = {
  confirmed: 4,
  likely: 3,
  uncertain: 2,
  "false-positive": 1,
};

function clampConfidence(value: number): number {
  return Math.max(0, Math.min(1, Number.isFinite(value) ? value : 0));
}

function uniqueReviews(reviews: readonly AiFindingReview[]): AiFindingReview[] {
  const byModel = new Map<string, AiFindingReview>();
  for (const review of reviews) {
    const model = review.model.trim();
    if (!model || byModel.has(model)) continue;
    byModel.set(model, review);
  }
  return [...byModel.values()];
}

function uniqueProviders(providers: readonly OpenAiCompatibleConfig[]): OpenAiCompatibleConfig[] {
  const byModel = new Map<string, OpenAiCompatibleConfig>();
  for (const provider of providers) {
    const model = provider.model.trim();
    if (!model || byModel.has(model)) continue;
    byModel.set(model, { ...provider, model });
  }
  return [...byModel.values()].slice(0, 10);
}

function safeFailureMessage(error: unknown, apiKey?: string): string {
  let message = error instanceof Error ? error.message : String(error);
  if (apiKey) message = message.replaceAll(apiKey, "[REDACTED]");
  return message.replace(/[\r\n]+/g, " ").slice(0, 500);
}

function winner<T extends string>(counts: Map<T, number>, rank: Record<T, number>): { value?: T; count: number; tied: boolean } {
  const ordered = [...counts.entries()].sort((a, b) => b[1] - a[1] || rank[b[0]] - rank[a[0]] || a[0].localeCompare(b[0]));
  const first = ordered[0];
  if (!first) return { count: 0, tied: false };
  const tied = ordered.length > 1 && ordered[1]?.[1] === first[1];
  return { value: first[0], count: first[1], tied };
}

function consensusGates(reviews: readonly AiFindingReview[]): ReviewConsensusGate[] {
  const questions = new Map<string, string>();
  for (const review of reviews) {
    for (const gate of review.gate) if (!questions.has(gate.id)) questions.set(gate.id, gate.question);
  }

  return [...questions.entries()].map(([id, question]) => {
    let yes = 0;
    let no = 0;
    let unknown = 0;
    for (const review of reviews) {
      const answer = review.gate.find((gate) => gate.id === id)?.answer ?? "unknown";
      if (answer === "yes") yes += 1;
      else if (answer === "no") no += 1;
      else unknown += 1;
    }
    const answer: ReviewAnswer = yes > no && yes > unknown
      ? "yes"
      : no > yes && no > unknown
        ? "no"
        : "unknown";
    return { id, question, answer, yes, no, unknown };
  });
}

export function buildReviewConsensus(
  input: readonly AiFindingReview[],
  options: { minimumReviewers?: number } = {},
): AiReviewConsensus {
  const minimumReviewers = Math.max(2, Math.min(10, options.minimumReviewers ?? 2));
  const reviews = uniqueReviews(input).slice(0, 10);
  const models = reviews.map((review) => review.model.trim());

  if (reviews.length < minimumReviewers) {
    return {
      schemaVersion: 1,
      verdict: "uncertain",
      severity: "unknown",
      confidence: 0,
      agreement: "insufficient",
      reviewerCount: reviews.length,
      models,
      agreeingModels: [],
      dissentingModels: models,
      gate: consensusGates(reviews),
      interpretation: "model-consensus-not-scanner-evidence",
    };
  }

  const verdictCounts = new Map<AiFindingReview["verdict"], number>();
  for (const review of reviews) verdictCounts.set(review.verdict, (verdictCounts.get(review.verdict) ?? 0) + 1);
  const selected = winner(verdictCounts, verdictRank);
  const hasMajority = selected.value !== undefined && selected.count > reviews.length / 2;
  const unanimous = selected.value !== undefined && selected.count === reviews.length;
  const consensusVerdict: AiFindingReview["verdict"] = hasMajority && !selected.tied ? selected.value ?? "uncertain" : "uncertain";
  const agreeing = reviews.filter((review) => review.verdict === consensusVerdict);
  const confidenceSource = agreeing.length > 0 ? agreeing : reviews;
  const confidence = confidenceSource.reduce((total, review) => total + clampConfidence(review.confidence), 0) / confidenceSource.length;
  const severitySource = consensusVerdict === "false-positive"
    ? agreeing
    : reviews.filter((review) => review.verdict !== "false-positive");
  const severity = (severitySource.length ? severitySource : reviews)
    .map((review) => review.severity)
    .sort((a, b) => severityRank[b] - severityRank[a])[0] ?? "unknown";
  const agreeingModels = reviews.filter((review) => review.verdict === consensusVerdict).map((review) => review.model.trim());
  const dissentingModels = reviews.filter((review) => review.verdict !== consensusVerdict).map((review) => review.model.trim());

  return {
    schemaVersion: 1,
    verdict: consensusVerdict,
    severity,
    confidence: Number(confidence.toFixed(4)),
    agreement: unanimous ? "unanimous" : hasMajority && !selected.tied ? "majority" : "split",
    reviewerCount: reviews.length,
    models,
    agreeingModels,
    dissentingModels,
    gate: consensusGates(reviews),
    interpretation: "model-consensus-not-scanner-evidence",
  };
}

/**
 * Execute independent defensive finding reviews with bounded concurrency and aggregate them.
 * A secret finding can never cross this orchestration boundary with source context, even when a
 * custom reviewer is injected. Provider failures are isolated and credentials are redacted from
 * returned diagnostics. Fewer than the configured minimum successful reviewers yields an
 * insufficient/uncertain consensus rather than silently lowering the requirement.
 */
export async function reviewFindingWithConsensus(
  finding: Finding,
  providers: readonly OpenAiCompatibleConfig[],
  context?: FindingContext,
  reviewInstructions?: string,
  options: MultiReviewOptions = {},
): Promise<MultiReviewConsensusResult> {
  if (finding.category === "secret" && context) {
    throw new Error("Source context is prohibited for secret findings at the multi-review boundary.");
  }

  const selected = uniqueProviders(providers);
  const minimumReviewers = Math.max(2, Math.min(10, options.minimumReviewers ?? 2));
  const concurrency = Math.max(1, Math.min(4, options.concurrency ?? 2));
  const reviewer = options.reviewer ?? reviewFinding;
  const queue = [...selected];
  const reviews: AiFindingReview[] = [];
  const failures: ReviewConsensusFailure[] = [];

  await Promise.all(Array.from({ length: Math.min(concurrency, Math.max(1, queue.length)) }, async () => {
    while (queue.length > 0) {
      const provider = queue.shift();
      if (!provider) return;
      try {
        const review = await reviewer(finding, provider, context, reviewInstructions);
        reviews.push(review);
      } catch (error) {
        failures.push({
          model: provider.model,
          message: safeFailureMessage(error, provider.apiKey),
        });
      }
    }
  }));

  reviews.sort((a, b) => a.model.localeCompare(b.model));
  failures.sort((a, b) => a.model.localeCompare(b.model));
  return {
    reviews,
    failures,
    consensus: buildReviewConsensus(reviews, { minimumReviewers }),
  };
}
