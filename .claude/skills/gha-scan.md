---
name: gha-scan
description: Scan GitHub Actions workflow files for security vulnerabilities. Use when creating, reviewing, or modifying .github/workflows/ YAML files.
---

# GHA Scanner Skill

Scan GitHub Actions workflow files for security misconfigurations, injection vulnerabilities, supply chain risks, and CI/CD hygiene issues. 25 checks across 8 categories.

## When to Activate

- User creates a new GitHub Actions workflow file
- User modifies an existing workflow
- User asks to review or audit their CI/CD security
- User asks "is my workflow secure?" or "scan my workflows"
- After generating any `.github/workflows/*.yml` file

## How It Works

1. Find all `.github/workflows/*.yml` and `.github/workflows/*.yaml` files in the current project
2. Read each workflow file
3. Run the checks below against each file
4. Report findings with severity, evidence, and remediation

## Running the Scanner

### Option A: Local files (no API needed)

Read all workflow files from `.github/workflows/` in the current project. For each file, check against the rules below. No GitHub API or tokens needed.

### Option B: Remote repo scan

If the user provides a repo name or URL, use the hosted scanner:

```bash
curl -s -X POST https://scan.defensive.works/api/scan \
  -H "Content-Type: application/json" \
  -d '{"repo":"owner/repo"}'
```

Parse the JSON response and present the findings.

### Option C: CLI (if available)

```bash
GITHUB_TOKEN=xxx node /path/to/gha-scanner/dist/cli.js owner/repo
```

## Security Checks (25 total)

### Supply Chain (4 checks)
- **Unpinned actions** (medium): `uses:` with semver tag (`@v4`) instead of SHA. Fix: pin to full 40-char commit SHA.
- **Mutable refs** (high): `uses:` with `@main`, `@master`, `@latest`. Fix: pin to SHA.
- **Known vulnerable actions** (critical): Cross-reference against known CVEs (tj-actions CVE-2025-30066, Trivy 2026, reviewdog, codecov). Skip if using fixed version.
- **Docker mutable tags** (high): `docker://image:latest` or no tag. Fix: pin to specific version or digest.

### Injection (3 checks)
- **Dangerous context in run block** (critical): `${{ github.event.issue.title }}`, `${{ github.event.pull_request.body }}`, `${{ github.head_ref }}`, `${{ github.event.pull_request.head.ref }}`, `${{ github.event.pull_request.head.repo.full_name }}` and similar attacker-controlled variables used directly in `run:` blocks. Fix: assign to env var first.
- **Event expression in run block** (low): Any `${{ github.event.* }}` in run blocks that isn't in the dangerous list. Risky pattern even if current property is safe.
- **Dispatch input injection** (medium): `${{ github.event.inputs.* }}` in run blocks. Requires write access but still a defense-in-depth issue.

### Dangerous Triggers (3 checks)
- **pull_request_target + checkout** (critical): Workflow uses `pull_request_target` AND checks out PR head code. Classic "pwn request" pattern.
- **pull_request_target + secrets** (high): Workflow uses `pull_request_target` AND references `${{ secrets.* }}`.
- **workflow_run artifacts** (medium): `workflow_run` trigger with `actions/download-artifact` without validation.

### Permissions (3 checks)
- **Missing permissions block** (medium): No top-level `permissions:` key. Fix: add explicit permissions.
- **Overly broad permissions** (high): `permissions: write-all` or 3+ write scopes. Fix: use least privilege.
- **Missing job-level permissions** (medium): Broad top-level without job-level overrides.

### Secrets Exposure (4 checks)
- **Secrets echoed to logs** (critical): `echo ${{ secrets.* }}` or similar in run blocks. Fix: never echo secrets.
- **Secrets as CLI arguments** (medium): Secrets inline in commands. Fix: use env vars.
- **Credential persistence** (medium): `actions/checkout` without `persist-credentials: false`.
- **Artifact leakage** (medium): `upload-artifact` with sensitive file patterns (.env, *.pem, *.key).

### Runner Security (3 checks)
- **Self-hosted + pull_request** (critical): Self-hosted runner with `pull_request` trigger. Fork PRs execute attacker code on your infra. Demonstrated at DEF CON 32 against Google, Microsoft, PyTorch.
- **Self-hosted + untrusted triggers** (high): Self-hosted with external input triggers.
- **Docker privilege escalation** (high): `docker run --privileged` or Docker socket mount in run blocks.

### CI/CD Hygiene (3 checks)
- **No concurrency** (info): Missing `concurrency:` group.
- **No timeout** (info): Missing `timeout-minutes:` (defaults to 6 hours).
- **continue-on-error** (medium): `continue-on-error: true` can mask security failures.

### Best Practices (2 checks)
- **No Dependabot for Actions** (medium): Missing `.github/dependabot.yml` with `github-actions` ecosystem.
- **No CODEOWNERS for workflows** (low): No CODEOWNERS rule for `.github/workflows/`.

## Output Format

For each finding, report:
- **Severity** (critical / high / medium / low / info)
- **Check ID** (e.g. `supply-chain/unpinned-actions`)
- **Title** (what was found)
- **File and line**
- **Evidence** (the problematic code)
- **Risk** (why it's dangerous, reference real attacks)
- **Remediation** (exact fix with code example)

## Inline Suppression

Users can suppress specific findings:
```yaml
- uses: some/action@main  # gha-scanner-ignore: supply-chain/mutable-refs
```

Requires explicit check ID. No blanket suppression.

## References

- Scanner: https://scan.defensive.works
- GitHub: https://github.com/raajheshkannaa/gha-scanner
- Check catalog: https://github.com/raajheshkannaa/gha-scanner/blob/main/docs/CHECKS.md
