import { describe, it, expect } from 'vitest';
import { dangerousTriggersChecks } from '../../lib/scanner/checks/dangerous-triggers';
import { makeContext, makeWorkflow } from '../helpers';

const findCheck = (id: string) => dangerousTriggersChecks.find(c => c.id === id)!;

describe('triggers/prt-checkout', () => {
  const check = findCheck('triggers/prt-checkout');

  it('flags pull_request_target with checkout of head ref', () => {
    const ctx = makeContext([makeWorkflow(`
name: PR Target
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.ref }}
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].checkId).toBe('triggers/prt-checkout');
  });

  it('does not flag pull_request_target without head ref checkout', () => {
    const ctx = makeContext([makeWorkflow(`
name: PR Target
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });

  it('skips workflow_call only trigger (no findings)', () => {
    const ctx = makeContext([makeWorkflow(`
name: Reusable
on: workflow_call
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.ref }}
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });

  it('flags pull_request_target with checkout of head sha', () => {
    const ctx = makeContext([makeWorkflow(`
name: PR Target
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
  });
});
