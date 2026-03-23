const REPO_REGEX =
  /^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?\/[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$/;

export function parseRepoInput(
  input: string
): { owner: string; repo: string } | null {
  const trimmed = input.trim();

  if (trimmed.length > 200) return null;

  // Direct owner/repo format
  if (REPO_REGEX.test(trimmed)) {
    const [owner, repo] = trimmed.split('/');
    return { owner, repo };
  }

  // GitHub URL formats
  try {
    let url: URL;
    if (trimmed.startsWith('http')) {
      url = new URL(trimmed);
    } else if (trimmed.startsWith('github.com')) {
      url = new URL(`https://${trimmed}`);
    } else {
      return null;
    }

    if (url.hostname !== 'github.com' && url.hostname !== 'www.github.com') {
      return null;
    }

    const parts = url.pathname.split('/').filter(Boolean);
    if (parts.length >= 2) {
      const owner = parts[0];
      const repo = parts[1].replace(/\.git$/, '');
      const combined = `${owner}/${repo}`;
      if (REPO_REGEX.test(combined)) {
        return { owner, repo };
      }
    }
  } catch {
    // Not a valid URL
  }

  return null;
}
