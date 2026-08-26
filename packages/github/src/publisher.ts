import type { GitHubCheckResult, GitHubPullRequestContext } from "./index.js";

export interface GitHubCheckPublication {
  id: number;
  htmlUrl?: string;
  status?: string;
  conclusion?: string;
}

export interface GitHubPublisherOptions {
  apiVersion?: string;
  userAgent?: string;
  fetch?: typeof globalThis.fetch;
}

interface GitHubCheckRunResponse {
  id?: unknown;
  html_url?: unknown;
  status?: unknown;
  conclusion?: unknown;
}

function repositoryParts(repository: string): { owner: string; name: string } {
  const match = /^([^/\s]+)\/([^/\s]+)$/.exec(repository.trim());
  if (!match?.[1] || !match[2]) throw new Error(`Invalid GitHub repository: ${repository}`);
  return { owner: match[1], name: match[2] };
}

function nonEmptyToken(token: string): string {
  const normalized = token.trim();
  if (!normalized) throw new Error("A GitHub token is required to publish a check run.");
  return normalized;
}

function responseString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function responseNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : undefined;
}

export function toGitHubCheckRunRequest(check: GitHubCheckResult): Record<string, unknown> {
  return {
    name: check.name,
    head_sha: check.headSha,
    status: "completed",
    conclusion: check.conclusion,
    output: check.output,
  };
}

/**
 * Publish a completed SynSec check to GitHub's Checks API.
 *
 * The destination host is fixed to api.github.com and the repository comes from validated
 * GitHub context. Scanner output never controls a request URL. The bearer token is used only
 * in the Authorization header and is never included in returned errors.
 */
export async function publishGitHubCheck(
  check: GitHubCheckResult,
  context: GitHubPullRequestContext,
  token: string,
  options: GitHubPublisherOptions = {},
): Promise<GitHubCheckPublication> {
  const authToken = nonEmptyToken(token);
  const { owner, name } = repositoryParts(context.repository);
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (!fetchImpl) throw new Error("No fetch implementation is available for GitHub check publication.");

  const url = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/check-runs`;
  const response = await fetchImpl(url, {
    method: "POST",
    redirect: "error",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${authToken}`,
      "Content-Type": "application/json",
      "User-Agent": options.userAgent?.trim() || "synsec/0.2",
      "X-GitHub-Api-Version": options.apiVersion?.trim() || "2022-11-28",
    },
    body: JSON.stringify(toGitHubCheckRunRequest(check)),
  });

  const text = await response.text();
  if (!response.ok) {
    const detail = text.replace(/[\r\n]+/g, " ").slice(0, 500).trim();
    throw new Error(`GitHub Checks API returned HTTP ${response.status}${detail ? `: ${detail}` : "."}`);
  }

  let payload: GitHubCheckRunResponse;
  try {
    payload = text ? (JSON.parse(text) as GitHubCheckRunResponse) : {};
  } catch {
    throw new Error("GitHub Checks API returned invalid JSON.");
  }

  const id = responseNumber(payload.id);
  if (!id) throw new Error("GitHub Checks API response did not include a valid check-run id.");
  const htmlUrl = responseString(payload.html_url);
  const status = responseString(payload.status);
  const conclusion = responseString(payload.conclusion);
  return {
    id,
    ...(htmlUrl ? { htmlUrl } : {}),
    ...(status ? { status } : {}),
    ...(conclusion ? { conclusion } : {}),
  };
}
