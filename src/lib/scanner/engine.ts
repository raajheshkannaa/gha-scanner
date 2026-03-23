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

  // Filter out suppressed findings via inline comments
  const { filtered, suppressedCount } = filterSuppressed(findings, context.workflows);
  if (suppressedCount > 0) {
    warnings.push(`${suppressedCount} finding(s) suppressed via inline comments.`);
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

function filterSuppressed(findings: Finding[], workflows: WorkflowFile[]): { filtered: Finding[]; suppressedCount: number } {
  const workflowLines = new Map<string, string[]>();
  for (const wf of workflows) {
    workflowLines.set(wf.path, wf.content.split('\n'));
  }

  let suppressedCount = 0;
  const filtered = findings.filter(f => {
    if (!f.line) return true; // Can't suppress without a line number
    const lines = workflowLines.get(f.file);
    if (!lines) return true;

    // Check the finding line and the line above for suppression comment
    const checkLines = [lines[f.line - 1], lines[f.line - 2]].filter(Boolean);
    for (const line of checkLines) {
      const match = line.match(/# gha-scanner-ignore(?::?\s*(.+))?/);
      if (match) {
        const specifiedCheck = match[1]?.trim();
        // If no specific check, suppress everything. If specific, match check ID.
        if (!specifiedCheck || specifiedCheck === f.checkId) {
          suppressedCount++;
          return false;
        }
      }
    }
    return true;
  });

  return { filtered, suppressedCount };
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
