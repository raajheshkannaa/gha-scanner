import { describe, it, expect } from 'vitest';
import { calculateScore, calculateGrade } from '../lib/scanner/scoring';
import type { Finding, CheckDefinition } from '../lib/scanner/types';

function makeFinding(checkId: string, severity: Finding['severity'] = 'medium'): Finding {
  return {
    checkId,
    severity,
    category: 'supply-chain',
    title: 'Test finding',
    description: 'Test',
    risk: 'Test',
    remediation: 'Test',
    file: 'test.yml',
    evidence: 'test',
  };
}

function makeCheck(id: string, severity: CheckDefinition['severity'] = 'medium'): CheckDefinition {
  return {
    id,
    name: `Check ${id}`,
    description: 'Test check',
    category: 'supply-chain',
    severity,
    run: () => [],
  };
}

describe('calculateScore', () => {
  it('returns score 100 and grade A with zero findings', () => {
    const checks = Array.from({ length: 25 }, (_, i) => makeCheck(`check-${i}`, 'medium'));
    const result = calculateScore([], checks);
    expect(result.score).toBe(100);
    expect(result.grade).toBe('A');
  });

  it('drops score significantly for 1 critical finding', () => {
    const checks = [
      makeCheck('critical-check', 'critical'),
      makeCheck('other-1', 'medium'),
      makeCheck('other-2', 'low'),
    ];
    const findings = [makeFinding('critical-check', 'critical')];
    const result = calculateScore(findings, checks);
    expect(result.score).toBeLessThan(90);
  });

  it('caps findings at 3 per check', () => {
    const checks = [makeCheck('the-check', 'medium')];
    // 5 findings for the same check, but only 3 should count
    const findings = Array.from({ length: 5 }, () => makeFinding('the-check', 'medium'));
    const resultCapped = calculateScore(findings, checks);

    // Compare: 3 findings should give same score as 5 findings (capped)
    const findings3 = Array.from({ length: 3 }, () => makeFinding('the-check', 'medium'));
    const result3 = calculateScore(findings3, checks);

    expect(resultCapped.score).toBe(result3.score);
  });

  it('returns low score when all checks fail maximally', () => {
    const checks = [
      makeCheck('c1', 'critical'),
      makeCheck('c2', 'high'),
      makeCheck('c3', 'medium'),
    ];
    const findings = [
      // 3 findings per check (max)
      ...Array.from({ length: 3 }, () => makeFinding('c1', 'critical')),
      ...Array.from({ length: 3 }, () => makeFinding('c2', 'high')),
      ...Array.from({ length: 3 }, () => makeFinding('c3', 'medium')),
    ];
    const result = calculateScore(findings, checks);
    expect(result.score).toBe(0);
    expect(result.grade).toBe('F');
  });

  it('returns score 100 and grade A with zero checks', () => {
    const result = calculateScore([], []);
    expect(result.score).toBe(100);
    expect(result.grade).toBe('A');
  });
});

describe('calculateGrade', () => {
  it('returns A for score 90', () => {
    expect(calculateGrade(90)).toBe('A');
  });

  it('returns B for score 89', () => {
    expect(calculateGrade(89)).toBe('B');
  });

  it('returns B for score 80', () => {
    expect(calculateGrade(80)).toBe('B');
  });

  it('returns C for score 79', () => {
    expect(calculateGrade(79)).toBe('C');
  });

  it('returns C for score 70', () => {
    expect(calculateGrade(70)).toBe('C');
  });

  it('returns D for score 69', () => {
    expect(calculateGrade(69)).toBe('D');
  });

  it('returns D for score 60', () => {
    expect(calculateGrade(60)).toBe('D');
  });

  it('returns F for score 59', () => {
    expect(calculateGrade(59)).toBe('F');
  });

  it('returns A for score 100', () => {
    expect(calculateGrade(100)).toBe('A');
  });

  it('returns F for score 0', () => {
    expect(calculateGrade(0)).toBe('F');
  });
});
