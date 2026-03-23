import pLimit from 'p-limit';
import type { RepoContext, WorkflowFile } from '../scanner/types';

// ---------------------------------------------------------------------------
// Error classes
// ---------------------------------------------------------------------------

export class GitHubError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GitHubError';
  }
}

export class GitHubNotFoundError extends GitHubError {
  constructor(owner: string, repo: string) {
    super(`Repository ${owner}/${repo} not found or is not accessible.`);
    this.name = 'GitHubNotFoundError';
  }
}

export class GitHubRateLimitError extends GitHubError {
  public readonly resetAt: Date;

  constructor(resetEpoch: number) {
    const resetAt = new Date(resetEpoch * 1000);
    super(`GitHub API rate limit exceeded. Resets at ${resetAt.toISOString()}.`);
    this.name = 'GitHubRateLimitError';
    this.resetAt = resetAt;
  }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const API_BASE = 'https://api.github.com';
const TIMEOUT_MS = 8_000;
const MAX_WORKFLOWS = 20;
const RATE_LIMIT_FLOOR = 500;
const WORKFLOW_PATH_RE = /^\.github\/workflows\/[a-zA-Z0-9_\-.]+\.ya?ml$/;

// ---------------------------------------------------------------------------
// Core fetch helper
// ---------------------------------------------------------------------------

interface RateLimitInfo {
  remaining: number;
  limit: number;
  reset: number;
}

function parseRateLimit(headers: Headers): RateLimitInfo {
  return {
    remaining: Number(headers.get('x-ratelimit-remaining') ?? -1),
    limit: Number(headers.get('x-ratelimit-limit') ?? -1),
    reset: Number(headers.get('x-ratelimit-reset') ?? 0),
  };
}

async function githubFetch(
  path: string,
  accept = 'application/vnd.github+json',
): Promise<{ body: unknown; rateLimit: RateLimitInfo }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  const headers: Record<string, string> = {
    Accept: accept,
    'X-GitHub-Api-Version': '2022-11-28',
  };

  const token = process.env.GITHUB_TOKEN;
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      headers,
      signal: controller.signal,
    });
  } catch (err: unknown) {
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new GitHubError('GitHub API request timed out.');
    }
    throw new GitHubError('Failed to connect to the GitHub API.');
  } finally {
    clearTimeout(timer);
  }

  const rateLimit = parseRateLimit(response.headers);

  if (response.status === 404) {
    throw new GitHubNotFoundError('unknown', 'unknown');
  }

  if (
    response.status === 403 &&
    rateLimit.remaining !== -1 &&
    rateLimit.remaining === 0
  ) {
    throw new GitHubRateLimitError(rateLimit.reset);
  }

  if (!response.ok) {
    throw new GitHubError(
      `GitHub API returned HTTP ${response.status}. Please try again later.`,
    );
  }

  const contentType = response.headers.get('content-type') ?? '';
  const body = contentType.includes('application/json')
    ? await response.json()
    : await response.text();

  return { body, rateLimit };
}

// ---------------------------------------------------------------------------
// Helper: fetch raw file content (returns null on 404)
// ---------------------------------------------------------------------------

async function fetchRawContent(
  owner: string,
  repo: string,
  path: string,
): Promise<{ content: string | null; rateLimit: RateLimitInfo }> {
  try {
    const { body, rateLimit } = await githubFetch(
      `/repos/${owner}/${repo}/contents/${path}`,
      'application/vnd.github.raw+json',
    );
    return { content: typeof body === 'string' ? body : JSON.stringify(body), rateLimit };
  } catch (err) {
    if (err instanceof GitHubNotFoundError) {
      return { content: null, rateLimit: { remaining: -1, limit: -1, reset: 0 } };
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Workflow file discovery
// ---------------------------------------------------------------------------

interface TreeEntry {
  path: string;
  mode: string;
  type: string;
  sha: string;
  size?: number;
}

async function discoverWorkflowPaths(
  owner: string,
  repo: string,
  branch: string,
): Promise<{ paths: string[]; rateLimit: RateLimitInfo }> {
  // Try the recursive tree first
  const { body, rateLimit } = await githubFetch(
    `/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`,
  );

  const tree = body as { tree: TreeEntry[]; truncated: boolean };

  if (tree.truncated) {
    // Fallback: list the workflows directory directly
    const fallback = await githubFetch(
      `/repos/${owner}/${repo}/contents/.github/workflows`,
    );
    const items = fallback.body as Array<{ name: string; path: string; type: string }>;
    const paths = items
      .filter((item) => item.type === 'file' && WORKFLOW_PATH_RE.test(item.path))
      .map((item) => item.path)
      .slice(0, MAX_WORKFLOWS);
    return { paths, rateLimit: fallback.rateLimit };
  }

  const paths = tree.tree
    .filter(
      (entry) =>
        entry.mode !== '120000' &&
        WORKFLOW_PATH_RE.test(entry.path),
    )
    .map((entry) => entry.path)
    .slice(0, MAX_WORKFLOWS);

  return { paths, rateLimit };
}

// ---------------------------------------------------------------------------
// Public: fetchRepoContext
// ---------------------------------------------------------------------------

export async function fetchRepoContext(
  owner: string,
  repo: string,
): Promise<RepoContext> {
  let latestRateLimit: RateLimitInfo = { remaining: -1, limit: -1, reset: 0 };

  function trackRate(rl: RateLimitInfo) {
    if (rl.remaining !== -1) {
      latestRateLimit = rl;
    }
  }

  function guardRateLimit() {
    if (
      latestRateLimit.remaining !== -1 &&
      latestRateLimit.remaining < RATE_LIMIT_FLOOR
    ) {
      throw new GitHubRateLimitError(latestRateLimit.reset);
    }
  }

  // Step 1 -- verify repo existence, get metadata
  const { body: repoData, rateLimit: repoRate } = await githubFetch(
    `/repos/${owner}/${repo}`,
  ).catch((err) => {
    if (err instanceof GitHubNotFoundError) {
      throw new GitHubNotFoundError(owner, repo);
    }
    throw err;
  });

  trackRate(repoRate);
  guardRateLimit();

  const repoInfo = repoData as {
    default_branch: string;
    private: boolean;
  };

  if (repoInfo.private) {
    throw new GitHubError(
      'Only public repositories can be scanned. This repository is private.',
    );
  }

  const defaultBranch = repoInfo.default_branch;

  // Fetch the branch ref to get head SHA
  const { body: branchData, rateLimit: branchRate } = await githubFetch(
    `/repos/${owner}/${repo}/branches/${defaultBranch}`,
  );
  trackRate(branchRate);
  guardRateLimit();

  const headSha = (branchData as { commit: { sha: string } }).commit.sha;

  // Step 2 -- discover workflow files
  const { paths: workflowPaths, rateLimit: treeRate } =
    await discoverWorkflowPaths(owner, repo, defaultBranch);
  trackRate(treeRate);
  guardRateLimit();

  // Step 3 -- fetch workflow contents in parallel (concurrency: 5)
  const limit = pLimit(5);

  const workflowPromises = workflowPaths.map((wfPath) =>
    limit(async (): Promise<WorkflowFile | null> => {
      const { content, rateLimit: rl } = await fetchRawContent(owner, repo, wfPath);
      trackRate(rl);
      if (!content) return null;

      let parsed: Record<string, unknown> | null = null;
      try {
        const yaml = await import('yaml');
        parsed = yaml.parse(content) as Record<string, unknown>;
      } catch {
        parsed = null;
      }

      const name = wfPath.split('/').pop() ?? wfPath;
      return { path: wfPath, name, content, parsed };
    }),
  );

  // Step 4 -- fetch dependabot config and CODEOWNERS in parallel
  const dependabotPromise = limit(async () => {
    const { content, rateLimit: rl } = await fetchRawContent(
      owner,
      repo,
      '.github/dependabot.yml',
    );
    trackRate(rl);
    if (content) return content;

    // Try .yaml variant
    const { content: yamlContent, rateLimit: rl2 } = await fetchRawContent(
      owner,
      repo,
      '.github/dependabot.yaml',
    );
    trackRate(rl2);
    return yamlContent;
  });

  const codeownersPromise = limit(async () => {
    const locations = [
      'CODEOWNERS',
      '.github/CODEOWNERS',
      'docs/CODEOWNERS',
    ];
    for (const loc of locations) {
      const { content, rateLimit: rl } = await fetchRawContent(owner, repo, loc);
      trackRate(rl);
      if (content) return content;
    }
    return null;
  });

  const [workflowResults, dependabotRaw, codeownersRaw] = await Promise.all([
    Promise.all(workflowPromises),
    dependabotPromise,
    codeownersPromise,
  ]);

  guardRateLimit();

  const workflows = workflowResults.filter(
    (w): w is WorkflowFile => w !== null,
  );

  let dependabotConfig: Record<string, unknown> | null = null;
  if (dependabotRaw) {
    try {
      const yaml = await import('yaml');
      dependabotConfig = yaml.parse(dependabotRaw) as Record<string, unknown>;
    } catch {
      dependabotConfig = null;
    }
  }

  return {
    owner,
    repo,
    defaultBranch,
    headSha,
    workflows,
    hasDependabot: dependabotRaw !== null,
    dependabotConfig,
    hasCodeowners: codeownersRaw !== null,
    codeownersContent: codeownersRaw,
  };
}
