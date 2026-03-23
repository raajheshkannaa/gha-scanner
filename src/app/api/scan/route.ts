import { NextRequest, NextResponse } from 'next/server';
import { parseRepoInput } from '@/lib/utils/parse-repo';
import { fetchRepoContext, GitHubNotFoundError, GitHubRateLimitError } from '@/lib/github/fetch-workflows';
import { runScan } from '@/lib/scanner/engine';
import { checkRateLimit } from '@/lib/rate-limit';

export async function POST(request: NextRequest) {
  try {
    // Rate limit check
    const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
      || request.headers.get('x-real-ip')
      || 'unknown';
    const rateCheck = await checkRateLimit(ip);
    if (!rateCheck.allowed) {
      return NextResponse.json(
        { error: 'Too many scans. Please wait a moment and try again.' },
        { status: 429, headers: { 'Retry-After': '60' } }
      );
    }

    // Parse request body
    let body: Record<string, unknown>;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json(
        { error: 'Invalid JSON in request body' },
        { status: 400 }
      );
    }
    const { repo: repoInput } = body;

    if (!repoInput || typeof repoInput !== 'string') {
      return NextResponse.json(
        { error: 'Missing or invalid repo parameter' },
        { status: 400 }
      );
    }

    // Parse repo input
    const parsed = parseRepoInput(repoInput);
    if (!parsed) {
      return NextResponse.json(
        { error: 'Invalid repository format. Use owner/repo or a GitHub URL.' },
        { status: 400 }
      );
    }

    const { owner, repo } = parsed;

    // Fetch repo context from GitHub API
    const context = await fetchRepoContext(owner, repo);

    // Run all checks
    const result = runScan(context);

    // Cap response size at 500KB
    const json = JSON.stringify(result);
    if (json.length > 500_000) {
      // Truncate findings to fit
      const truncated = { ...result };
      truncated.findings = result.findings.slice(0, 50);
      truncated.warnings = [...result.warnings, `Findings truncated from ${result.findings.length} to 50 due to response size limits`];
      return NextResponse.json(truncated);
    }

    return NextResponse.json(result);
  } catch (err) {
    // Handle known error types with safe messages
    if (err instanceof GitHubNotFoundError) {
      return NextResponse.json(
        { error: 'Repository not found. Make sure it exists and is public.' },
        { status: 404 }
      );
    }

    if (err instanceof GitHubRateLimitError) {
      return NextResponse.json(
        { error: 'GitHub API rate limit reached. Please try again later.' },
        { status: 429 }
      );
    }

    // Generic error - never expose internals
    console.error('Scan error:', err instanceof Error ? err.message : 'unknown');
    return NextResponse.json(
      { error: 'An error occurred while scanning. Please try again.' },
      { status: 500 }
    );
  }
}
