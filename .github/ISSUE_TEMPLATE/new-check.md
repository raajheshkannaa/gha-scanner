---
name: New Security Check
about: Propose a new security check for the scanner
title: '[CHECK] '
labels: enhancement
---

## Check Summary

**Name:** (e.g., "Reusable workflow without pinned ref")
**Category:** (supply-chain | injection | dangerous-triggers | permissions | secrets-exposure | runner-security | ci-cd-hygiene | best-practices)
**Proposed Severity:** (critical | high | medium | low | info)

## What should the check detect?

Describe the specific workflow pattern or misconfiguration this check should flag.

## Why is this a security concern?

Explain the risk. Link to any CVEs, advisories, blog posts, or real-world incidents that demonstrate the impact.

## Example workflow that should trigger this check

```yaml
# Paste a minimal workflow YAML that demonstrates the vulnerable pattern
name: example
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "replace with vulnerable pattern"
```

## Expected finding output

What should the title, description, and remediation look like?

## Example workflow that should NOT trigger this check

```yaml
# Paste a minimal workflow YAML that demonstrates the safe/correct pattern
```

## Additional context

Any other information, references, or related checks.
