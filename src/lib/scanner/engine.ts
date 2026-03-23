import { Finding, RepoContext, ScanResult, CategorySummary, CATEGORY_LABELS, Category, WorkflowFile } from './types';
import { allChecks } from './checks';
import { calculateScore } from './scoring';

export function runScan(context: RepoContext): ScanResult {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const warnings: string[] = [...context.parseWarnings];
  let passingChecks = 0;
  const hasParseFailures = context.workflows.some(w => w.parsed === null);

  if (context.workflows.length === 0) {
    warnings.push('No workflow files found in this repository. Score reflects the absence of workflows, not their security.');
  }

  for (const check of allChecks) {
    try {
      const checkFindings = check.run(context);
      if (checkFindings.length === 0) {
        passingChecks++;
      }
      findings.push(...checkFindings);
    } catch (err) {
      warnings.push(`Check ${check.id} failed: ${err instanceof Error ? err.message : 'unknown error'}`);
    }
  }

  // Filter out suppressed findings via inline comments (requires explicit check ID)
  const { filtered, suppressedCount, suppressedChecks } = filterSuppressed(findings, context.workflows);
  if (suppressedCount > 0) {
    warnings.push(`${suppressedCount} finding(s) suppressed via inline comments: ${suppressedChecks.join(', ')}`);
  }

  const { score, grade } = calculateScore(filtered, allChecks);
  const categories = buildCategorySummaries(filtered);
  const duration = Date.now() - startTime;

  return {
    schemaVersion: 1,
    repo: `${context.owner}/${context.repo}`,
    headSha: context.headSha,
    scannedAt: new Date().toISOString(),
    duration,
    score,
    grade,
    totalChecks: allChecks.length,
    passingChecks,
    findings: filtered,
    categories,
    workflowCount: context.workflows.length,
    partial: hasParseFailures,
    warnings,
  };
}

function filterSuppressed(findings: Finding[], workflows: WorkflowFile[]): { filtered: Finding[]; suppressedCount: number; suppressedChecks: string[] } {
  const workflowLines = new Map<string, string[]>();
  for (const wf of workflows) {
    workflowLines.set(wf.path, wf.content.split(/\r?\n/));
  }

  // Regex requires the suppression comment to appear after YAML content (not inside a string)
  // Matches: `  # gha-scanner-ignore: check-id` or `- uses: foo@bar # gha-scanner-ignore: check-id`
  const SUPPRESS_RE = /\s# gha-scanner-ignore:\s*(\S+)/;

  let suppressedCount = 0;
  const suppressedChecks: string[] = [];
  const filtered = findings.filter(f => {
    if (!f.line || f.line < 1) return true;
    const lines = workflowLines.get(f.file);
    if (!lines || f.line > lines.length) return true;

    // Check the finding line and the line above
    const linesToCheck = [lines[f.line - 1]];
    if (f.line >= 2) linesToCheck.push(lines[f.line - 2]);

    for (const line of linesToCheck) {
      if (!line) continue;
      const match = line.match(SUPPRESS_RE);
      if (match) {
        const specifiedCheck = match[1].trim();
        // Must specify a check ID (no blanket suppression)
        if (specifiedCheck === f.checkId) {
          suppressedCount++;
          suppressedChecks.push(`${f.checkId} in ${f.file}:${f.line}`);
          return false;
        }
      }
    }
    return true;
  });

  return { filtered, suppressedCount, suppressedChecks };
}

function buildCategorySummaries(findings: Finding[]): CategorySummary[] {
  const map = new Map<Category, CategorySummary>();
  for (const cat of Object.keys(CATEGORY_LABELS) as Category[]) {
    map.set(cat, { category: cat, label: CATEGORY_LABELS[cat], totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  }
  for (const f of findings) {
    const s = map.get(f.category);
    if (s) {
      s.totalFindings++;
      s[f.severity]++;
    }
  }
  return Array.from(map.values());
}
