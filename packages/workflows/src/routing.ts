export type ModelTask =
  | "fast-classifier"
  | "security-reasoner"
  | "code-reasoner"
  | "report-writer"
  | "verifier";

export type ModelPrivacy = "local" | "private-remote" | "remote";

export interface ModelCandidate {
  id: string;
  tasks: readonly ModelTask[];
  costTier: 0 | 1 | 2 | 3;
  latencyTier: 0 | 1 | 2 | 3;
  privacy: ModelPrivacy;
  supportsSourceContext: boolean;
  enabled?: boolean;
}

export interface ModelRoutingRequest {
  task: ModelTask;
  sourceContextRequested: boolean;
  maxCostTier?: 0 | 1 | 2 | 3;
  requireLocal?: boolean;
  preferLocal?: boolean;
}

export interface ModelRoutingDecision {
  candidate: ModelCandidate;
  reason: string[];
}

export interface ModelSetRoutingDecision {
  candidates: ModelCandidate[];
  reason: string[];
}

function privacyRank(privacy: ModelPrivacy): number {
  if (privacy === "local") return 0;
  if (privacy === "private-remote") return 1;
  return 2;
}

function eligible(candidate: ModelCandidate, request: ModelRoutingRequest): boolean {
  if (candidate.enabled === false) return false;
  if (!candidate.tasks.includes(request.task)) return false;
  if (request.sourceContextRequested && !candidate.supportsSourceContext) return false;
  if (request.maxCostTier !== undefined && candidate.costTier > request.maxCostTier) return false;
  if (request.requireLocal && candidate.privacy !== "local") return false;
  return true;
}

function constraints(request: ModelRoutingRequest): string[] {
  return [
    `task=${request.task}`,
    `sourceContext=${request.sourceContextRequested ? "required" : "not-required"}`,
    request.maxCostTier !== undefined ? `maxCostTier=${request.maxCostTier}` : undefined,
    request.requireLocal ? "privacy=local-only" : undefined,
  ].filter((value): value is string => value !== undefined);
}

function rankedEligible(candidates: readonly ModelCandidate[], request: ModelRoutingRequest): ModelCandidate[] {
  return candidates.filter((candidate) => eligible(candidate, request)).sort((left, right) => {
    if (request.preferLocal) {
      const privacyDifference = privacyRank(left.privacy) - privacyRank(right.privacy);
      if (privacyDifference !== 0) return privacyDifference;
    }
    return left.costTier - right.costTier
      || left.latencyTier - right.latencyTier
      || privacyRank(left.privacy) - privacyRank(right.privacy)
      || left.id.localeCompare(right.id);
  });
}

export function routeModel(
  candidates: readonly ModelCandidate[],
  request: ModelRoutingRequest,
): ModelRoutingDecision {
  const ranked = rankedEligible(candidates, request);
  if (ranked.length === 0) {
    throw new Error(`No model candidate satisfies routing constraints: ${constraints(request).join(", ")}.`);
  }

  const candidate = ranked[0];
  if (!candidate) throw new Error("Model routing produced no candidate after eligibility filtering.");

  const reason = [
    `supports ${request.task}`,
    `cost tier ${candidate.costTier}`,
    `latency tier ${candidate.latencyTier}`,
    `privacy ${candidate.privacy}`,
  ];
  if (request.sourceContextRequested) reason.push("permits source context");
  if (request.preferLocal && candidate.privacy === "local") reason.push("local preference satisfied");

  return { candidate, reason };
}

/**
 * Select a deterministic set of distinct model identities for reviewer/verifier consensus.
 * The request's privacy, source-context, and cost constraints are applied to every member.
 * Insufficient eligible models fail closed instead of silently reducing reviewer count.
 */
export function routeModelSet(
  candidates: readonly ModelCandidate[],
  request: ModelRoutingRequest,
  count = 2,
): ModelSetRoutingDecision {
  if (!Number.isInteger(count) || count < 2 || count > 10) {
    throw new Error("Consensus model count must be an integer between 2 and 10.");
  }

  const seen = new Set<string>();
  const ranked = rankedEligible(candidates, request).filter((candidate) => {
    const id = candidate.id.trim();
    if (!id || seen.has(id)) return false;
    seen.add(id);
    return true;
  });
  if (ranked.length < count) {
    throw new Error(
      `Only ${ranked.length} distinct model candidate(s) satisfy consensus routing constraints; ${count} required: ${constraints(request).join(", ")}.`,
    );
  }

  const selected = ranked.slice(0, count);
  return {
    candidates: selected,
    reason: [
      `selected ${count} distinct models for ${request.task}`,
      request.sourceContextRequested ? "all permit source context" : "source context not required",
      request.requireLocal ? "all are local" : request.preferLocal ? "local preference applied" : "standard privacy ranking applied",
      "cost/latency constraints preserved for every reviewer",
    ],
  };
}
