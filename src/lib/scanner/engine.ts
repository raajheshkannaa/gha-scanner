import { Finding, RepoContext, ScanResult, CategorySummary, CATEGORY_LABELS, Category } from './types';
import { allChecks } from './checks';
import { calculateScore } from './scoring';

export function runScan(context: RepoContext): ScanResult {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const warnings: string[] = [];
  let passingChecks = 0;

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

  const { score, grade } = calculateScore(findings, allChecks);
  const categories = buildCategorySummaries(findings);
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
    findings,
    categories,
    workflowCount: context.workflows.length,
    partial: false,
    warnings,
  };
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
