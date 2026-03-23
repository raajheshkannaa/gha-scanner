---
name: False Positive Report
about: Report a finding that should not have been flagged
title: '[FALSE POSITIVE] '
labels: bug, false-positive
---

## Check that produced the false positive

**Check ID:** (e.g., `supply-chain/unpinned-actions`)
**Severity reported:** (critical | high | medium | low | info)

## Repository scanned

Provide the repository name or a link. If the repository is private, include the relevant workflow YAML below instead.

## Workflow file that triggered the finding

```yaml
# Paste the full workflow YAML or the relevant section that was flagged
```

## Finding output

Paste or describe the finding title, description, and evidence reported by the scanner.

## Why this is a false positive

Explain why this finding is incorrect. For example:
- The pattern matched is not actually vulnerable in this context
- The check does not account for a mitigating factor present in the workflow
- The matched string is in a comment or inactive code path

## Expected behavior

What should the scanner do instead? Options:
- Skip this pattern entirely
- Lower the severity
- Add an exception for this specific case

## Additional context

Any other information that helps reproduce or understand the issue.
