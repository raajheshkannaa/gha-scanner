import { describe, it, expect } from 'vitest';
import { supplyChainChecks } from '../../lib/scanner/checks/supply-chain';
import { makeContext, makeWorkflow } from '../helpers';

const findCheck = (id: string) => supplyChainChecks.find(c => c.id === id)!;

describe('supply-chain/unpinned-actions', () => {
  const check = findCheck('supply-chain/unpinned-actions');

  it('flags action pinned by semver tag', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].evidence).toContain('actions/checkout@v4');
  });

  it('does not flag action pinned to 40-char SHA', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });

  it('does not flag local actions', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./local-action
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });
});

describe('supply-chain/mutable-refs', () => {
  const check = findCheck('supply-chain/mutable-refs');

  it('flags action pinned to mutable branch ref (main)', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: owner/action@main
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('high');
    expect(findings[0].evidence).toContain('owner/action@main');
  });

  it('does not flag action pinned to semver tag', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: owner/action@v1.2.3
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });

  it('reports medium severity for same-org action', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: test-owner/action@main
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('medium');
  });
});

describe('supply-chain/known-vulnerable', () => {
  const check = findCheck('supply-chain/known-vulnerable');

  it('flags known vulnerable action at affected version', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@v45
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].title).toContain('tj-actions/changed-files');
  });

  it('does NOT flag known vulnerable action at fixed version', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@v46.0.1
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });

  it('does NOT flag known vulnerable action pinned to SHA', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@a81bbbf8298c0fa03ea29cdc473d45769f953675
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });
});

describe('supply-chain/docker-mutable-tags', () => {
  const check = findCheck('supply-chain/docker-mutable-tags');

  it('flags docker action with :latest tag', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://myimage:latest
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('high');
  });

  it('does not flag docker action with specific version tag', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://myimage:1.2.3
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(0);
  });

  it('flags docker action with no tag (implicit latest)', () => {
    const ctx = makeContext([makeWorkflow(`
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://myimage
`)]);
    const findings = check.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].description).toContain('implicit latest');
  });
});
