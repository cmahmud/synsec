import type { OpenAiCompatibleConfig } from "@synsec/ai";

const MAX_MODELS = 10;
const MAX_CONCURRENCY = 4;

export interface AiReviewSelectionInput {
  singleModel?: string;
  multipleModels?: string;
  configuredModel?: string;
  environmentModel?: string;
  baseUrl?: string;
  apiKey?: string;
  minimumReviewers?: number;
  concurrency?: number;
}

export interface AiReviewSelection {
  mode: "single" | "consensus";
  models: string[];
  providers: OpenAiCompatibleConfig[];
  minimumReviewers: number;
  concurrency: number;
}

function cleanModel(value: string | undefined): string | undefined {
  const normalized = value?.trim();
  if (!normalized) return undefined;
  if (normalized.length > 200 || /[\r\n\0]/.test(normalized)) {
    throw new Error("AI model id contains unsupported characters or exceeds 200 characters.");
  }
  return normalized;
}

function parseMultiple(value: string): string[] {
  const models = value.split(",").map((item) => cleanModel(item)).filter((item): item is string => Boolean(item));
  const unique = [...new Set(models)];
  if (unique.length < 2) throw new Error("--ai-models requires at least two unique model ids.");
  if (unique.length > MAX_MODELS) throw new Error(`--ai-models supports at most ${MAX_MODELS} unique model ids.`);
  return unique;
}

function boundedInteger(value: number | undefined, fallback: number, minimum: number, maximum: number, name: string): number {
  const normalized = value ?? fallback;
  if (!Number.isSafeInteger(normalized) || normalized < minimum || normalized > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}.`);
  }
  return normalized;
}

export function resolveAiReviewSelection(input: AiReviewSelectionInput): AiReviewSelection {
  const baseUrl = input.baseUrl?.trim();
  if (!baseUrl) throw new Error("AI review is enabled but no base URL is configured. Set SYNSEC_AI_BASE_URL or --ai-base-url.");
  if (/[\r\n\0]/.test(baseUrl) || baseUrl.length > 2048) throw new Error("AI base URL is invalid.");

  const explicitSingle = cleanModel(input.singleModel);
  const explicitMultiple = input.multipleModels?.trim();
  if (explicitSingle && explicitMultiple) {
    throw new Error("Use either --ai-model or --ai-models, not both.");
  }

  const models = explicitMultiple
    ? parseMultiple(explicitMultiple)
    : [explicitSingle ?? cleanModel(input.configuredModel) ?? cleanModel(input.environmentModel)].filter((item): item is string => Boolean(item));
  if (models.length === 0) {
    throw new Error("AI review is enabled but no model is configured. Set SYNSEC_AI_MODEL, --ai-model, or --ai-models.");
  }

  const mode = models.length > 1 ? "consensus" : "single";
  const minimumReviewers = mode === "consensus"
    ? boundedInteger(input.minimumReviewers, 2, 2, models.length, "--ai-min-reviewers")
    : 1;
  const concurrency = mode === "consensus"
    ? boundedInteger(input.concurrency, Math.min(2, models.length), 1, Math.min(MAX_CONCURRENCY, models.length), "--ai-review-concurrency")
    : 1;

  const providers = models.map((model): OpenAiCompatibleConfig => input.apiKey
    ? { baseUrl, model, apiKey: input.apiKey }
    : { baseUrl, model });
  return { mode, models, providers, minimumReviewers, concurrency };
}
