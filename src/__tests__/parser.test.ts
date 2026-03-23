import { describe, it, expect } from 'vitest';
import { parseWorkflowYaml, findLineNumber } from '../lib/scanner/parser';

describe('parseWorkflowYaml', () => {
  it('parses valid workflow YAML', () => {
    const yaml = `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`;
    const result = parseWorkflowYaml(yaml, 'ci.yml');
    expect(result.parsed).not.toBeNull();
    expect(result.error).toBeNull();
    expect(result.parsed!.name).toBe('CI');
  });

  it('returns null with error for empty string', () => {
    const result = parseWorkflowYaml('', 'empty.yml');
    expect(result.parsed).toBeNull();
    expect(result.error).toContain('empty.yml');
  });

  it('returns null with error for invalid YAML (random text)', () => {
    const result = parseWorkflowYaml('{{{{not yaml at all!!!!', 'bad.yml');
    expect(result.parsed).toBeNull();
    expect(result.error).toContain('bad.yml');
    expect(result.error).toContain('parse error');
  });

  it('returns null with error for YAML array (not object)', () => {
    const result = parseWorkflowYaml('- item1\n- item2\n', 'array.yml');
    expect(result.parsed).toBeNull();
    expect(result.error).toContain('Not a valid YAML object');
  });

  it('returns null with size error for file > 1MB', () => {
    const bigContent = 'a'.repeat(1_000_001);
    const result = parseWorkflowYaml(bigContent, 'huge.yml');
    expect(result.parsed).toBeNull();
    expect(result.error).toContain('size limit');
    expect(result.error).toContain('huge.yml');
  });

  it('parses YAML with aliases under limit', () => {
    const yaml = `
anchors:
  - &default_runner ubuntu-latest
name: CI
on: push
jobs:
  build:
    runs-on: *default_runner
    steps:
      - uses: actions/checkout@v4
`;
    const result = parseWorkflowYaml(yaml, 'alias.yml');
    expect(result.parsed).not.toBeNull();
    expect(result.error).toBeNull();
  });

  it('parses valid workflow with jobs/steps into correct structure', () => {
    const yaml = `
name: Test
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run tests
        run: npm test
`;
    const result = parseWorkflowYaml(yaml, 'test.yml');
    expect(result.parsed).not.toBeNull();
    const jobs = result.parsed!.jobs as Record<string, unknown>;
    expect(jobs).toBeDefined();
    const testJob = jobs.test as Record<string, unknown>;
    expect(testJob['runs-on']).toBe('ubuntu-latest');
    const steps = testJob.steps as Array<Record<string, unknown>>;
    expect(steps).toHaveLength(2);
    expect(steps[0].uses).toBe('actions/checkout@v4');
    expect(steps[1].run).toBe('npm test');
  });
});

describe('findLineNumber', () => {
  const content = `line one
line two
line three
line four
line five`;

  it('finds text on line 1', () => {
    expect(findLineNumber(content, 'line one')).toBe(1);
  });

  it('finds text on line 5', () => {
    expect(findLineNumber(content, 'line five')).toBe(5);
  });

  it('returns undefined for text not found', () => {
    expect(findLineNumber(content, 'does not exist')).toBeUndefined();
  });
});
