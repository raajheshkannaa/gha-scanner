import { Finding, CheckDefinition, SEVERITY_WEIGHTS } from './types';

const MAX_FINDINGS_PER_CHECK = 3;

export function calculateScore(
  findings: Finding[],
  checks: CheckDefinition[]
): { score: number; grade: 'A' | 'B' | 'C' | 'D' | 'F' } {
  // Max possible weight: sum of all check severity weights * MAX_FINDINGS_PER_CHECK
  // But we weight by unique checks that failed, capped at MAX_FINDINGS_PER_CHECK per check
  const maxPossibleWeight = checks.reduce(
    (sum, check) => sum + SEVERITY_WEIGHTS[check.severity] * MAX_FINDINGS_PER_CHECK,
    0
  );

  if (maxPossibleWeight === 0) {
    return { score: 100, grade: 'A' };
  }

  // Group findings by check ID, cap at MAX per check
  const findingsByCheck = new Map<string, Finding[]>();
  for (const finding of findings) {
    const existing = findingsByCheck.get(finding.checkId) || [];
    findingsByCheck.set(finding.checkId, existing);
    if (existing.length < MAX_FINDINGS_PER_CHECK) {
      existing.push(finding);
    }
  }

  // Calculate failed weight
  let failedWeight = 0;
  findingsByCheck.forEach((checkFindings, checkId) => {
    const check = checks.find(c => c.id === checkId);
    if (check) {
      failedWeight += SEVERITY_WEIGHTS[check.severity] * checkFindings.length;
    }
  });

  const score = Math.round(100 * (1 - failedWeight / maxPossibleWeight));
  const clampedScore = Math.max(0, Math.min(100, score));
  const grade = calculateGrade(clampedScore);

  return { score: clampedScore, grade };
}

export function calculateGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}
