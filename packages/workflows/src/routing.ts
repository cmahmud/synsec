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

export function routeModel(
  candidates: readonly ModelCandidate[],
  request: ModelRoutingRequest,
): ModelRoutingDecision {
  const matching = candidates.filter((candidate) => eligible(candidate, request));
  if (matching.length === 0) {
    const constraints = [
      `task=${request.task}`,
      `sourceContext=${request.sourceContextRequested ? "required" : "not-required"}`,
      request.maxCostTier !== undefined ? `maxCostTier=${request.maxCostTier}` : undefined,
      request.requireLocal ? "privacy=local-only" : undefined,
    ].filter((value): value is string => value !== undefined);
    throw new Error(`No model candidate satisfies routing constraints: ${constraints.join(", ")}.`);
  }

  const ranked = [...matching].sort((left, right) => {
    if (request.preferLocal) {
      const privacyDifference = privacyRank(left.privacy) - privacyRank(right.privacy);
      if (privacyDifference !== 0) return privacyDifference;
    }
    return left.costTier - right.costTier
      || left.latencyTier - right.latencyTier
      || privacyRank(left.privacy) - privacyRank(right.privacy)
      || left.id.localeCompare(right.id);
  });

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
