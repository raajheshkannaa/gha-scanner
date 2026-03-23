import { describe, it, expect } from 'vitest';
import { parseRepoInput } from '../lib/utils/parse-repo';

describe('parseRepoInput', () => {
  it('parses "owner/repo" format', () => {
    expect(parseRepoInput('owner/repo')).toEqual({ owner: 'owner', repo: 'repo' });
  });

  it('parses full GitHub URL', () => {
    expect(parseRepoInput('https://github.com/owner/repo')).toEqual({ owner: 'owner', repo: 'repo' });
  });

  it('parses GitHub URL with .git suffix', () => {
    expect(parseRepoInput('https://github.com/owner/repo.git')).toEqual({ owner: 'owner', repo: 'repo' });
  });

  it('parses URL without protocol (github.com/owner/repo)', () => {
    expect(parseRepoInput('github.com/owner/repo')).toEqual({ owner: 'owner', repo: 'repo' });
  });

  it('returns null for empty string', () => {
    expect(parseRepoInput('')).toBeNull();
  });

  it('returns null for single word (invalid)', () => {
    expect(parseRepoInput('invalid')).toBeNull();
  });

  it('extracts owner/repo from URL with extra path segments', () => {
    const result = parseRepoInput('https://github.com/a/b/c/d');
    expect(result).toEqual({ owner: 'a', repo: 'b' });
  });

  it('returns null for very long input (>200 chars)', () => {
    const longInput = 'a'.repeat(201);
    expect(parseRepoInput(longInput)).toBeNull();
  });

  it('returns null for path traversal attempt', () => {
    expect(parseRepoInput('../traversal')).toBeNull();
  });

  it('trims whitespace around input', () => {
    expect(parseRepoInput('  owner/repo  ')).toEqual({ owner: 'owner', repo: 'repo' });
  });

  it('returns null for non-github URL', () => {
    expect(parseRepoInput('https://gitlab.com/owner/repo')).toBeNull();
  });
});
