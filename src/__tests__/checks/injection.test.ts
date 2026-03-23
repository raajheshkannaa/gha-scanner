import { describe, it, expect } from 'vitest';
import { injectionChecks } from '../../lib/scanner/checks/injection';
import { makeContext, makeWorkflow } from '../helpers';

const findCheck = (id: string) => injectionChecks.find(c => c.id === id)!;

describe('injection/dangerous-contexts', () => {
  const check = findCheck('injection/dangerous-contexts');

  it('flags dangerous context in run block (issue title)', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: issues
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - name: Echo title
        run: echo "\${{ github.event.issue.title }}"
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].evidence).toContain('github.event.issue.title');
  });

  it('does not flag safe context like github.sha in run block', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "\${{ github.sha }}"
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });

  it('does not flag expression in env block (not in run)', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: issues
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - name: Safe step
        env:
          TITLE: "\${{ github.event.issue.title }}"
        run: echo "$TITLE"
`)]);
    // The check only looks at run: blocks, not env: blocks
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });
});

describe('injection/expression-in-run', () => {
  const check = findCheck('injection/expression-in-run');

  it('does not flag safe event property (pull_request.number)', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "PR #\${{ github.event.pull_request.number }}"
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });

  it('flags unknown event property not in safe or dangerous list', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "\${{ github.event.some_unknown_prop }}"
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('low');
  });
});

describe('injection/dispatch-input', () => {
  const check = findCheck('injection/dispatch-input');

  it('flags dispatch input used in run block', () => {
    const ctx = makeContext([makeWorkflow(`
name: Deploy
on:
  workflow_dispatch:
    inputs:
      environment:
        description: Target env
        required: true
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Deploying to \${{ github.event.inputs.environment }}"
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].evidence).toContain('github.event.inputs.environment');
  });

  it('does not flag when there is no workflow_dispatch trigger', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });
});
