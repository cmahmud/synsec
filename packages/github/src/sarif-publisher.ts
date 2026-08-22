import { gzipSync } from "node:zlib";
import type { SynSecReport } from "@synsec/report";
import { toSarif } from "@synsec/report";
import type { GitHubPullRequestContext } from "./index.js";
import { reportMatchesGitHubCommit } from "./orchestrator.js";
import type { GitHubPublisherOptions } from "./publisher.js";

const MAX_COMPRESSED_SARIF_BYTES = 10 * 1024 * 1024;

export interface GitHubSarifPublication {
  id: string;
  url?: string;
  commitSha: string;
  ref: string;
  compressedBytes: number;
}

function repositoryParts(repository: string): [string, string] {
  const match = /^([^/\s]+)\/([^/\s]+)$/.exec(repository);
  if (!match?.[1] || !match[2]) throw new Error("Invalid GitHub repository in publication context.");
  return [encodeURIComponent(match[1]), encodeURIComponent(match[2])];
}

export function sarifRefForContext(context: GitHubPullRequestContext): string {
  if (context.pullRequestNumber) return `refs/pull/${context.pullRequestNumber}/head`;
  if (context.ref?.startsWith("refs/")) return context.ref;
  if (context.headRef) return `refs/heads/${context.headRef}`;
  throw new Error("GitHub SARIF publication requires a fully qualified repository ref.");
}

function safeResponseText(value: string, token: string): string {
  return value.replaceAll(token, "[REDACTED]").replace(/[\r\n]+/g, " ").slice(0, 500);
}

/**
 * Upload one completed report as SARIF to GitHub code scanning. The destination is derived only
 * from validated GitHub context and is always api.github.com; scanner/report content cannot choose
 * a host. The report must identify the same commit being published.
 */
export async function publishGitHubSarif(
  report: SynSecReport,
  context: GitHubPullRequestContext,
  token: string,
  options: GitHubPublisherOptions = {},
): Promise<GitHubSarifPublication> {
  const reportSha = report.target.commitSha?.trim();
  if (!reportSha) throw new Error("GitHub SARIF publication requires a report commit SHA.");
  if (!reportMatchesGitHubCommit(reportSha, context.sha)) {
    throw new Error("SynSec report commit does not match the GitHub commit selected for SARIF publication.");
  }
  if (!token.trim()) throw new Error("GitHub SARIF publication requires a non-empty token.");

  const ref = sarifRefForContext(context);
  const sarif = Buffer.from(JSON.stringify(toSarif(report)), "utf8");
  const compressed = gzipSync(sarif, { level: 9 });
  if (compressed.byteLength > MAX_COMPRESSED_SARIF_BYTES) {
    throw new Error(`Compressed SARIF exceeds the ${MAX_COMPRESSED_SARIF_BYTES}-byte GitHub upload limit.`);
  }

  const [owner, repository] = repositoryParts(context.repository);
  const endpoint = `https://api.github.com/repos/${owner}/${repository}/code-scanning/sarifs`;
  const transport = options.fetch ?? fetch;
  const response = await transport(endpoint, {
    method: "POST",
    redirect: "error",
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      "user-agent": options.userAgent ?? "synsec/0.2",
      "x-github-api-version": options.apiVersion ?? "2022-11-28",
    },
    body: JSON.stringify({
      commit_sha: context.sha,
      ref,
      sarif: compressed.toString("base64"),
    }),
  });

  if (!response.ok) {
    const detail = safeResponseText(await response.text(), token);
    throw new Error(`GitHub SARIF API returned HTTP ${response.status}${detail ? `: ${detail}` : ""}.`);
  }

  const payload = await response.json() as { id?: unknown; url?: unknown };
  if (typeof payload.id !== "string" || !payload.id.trim()) {
    throw new Error("GitHub SARIF API returned no upload id.");
  }

  return {
    id: payload.id,
    ...(typeof payload.url === "string" && payload.url ? { url: payload.url } : {}),
    commitSha: context.sha,
    ref,
    compressedBytes: compressed.byteLength,
  };
}
