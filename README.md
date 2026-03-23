# GHA Scanner

Static analysis for GitHub Actions workflows. Finds security misconfigurations, injection vulnerabilities, supply chain risks, and CI/CD hygiene issues.

25 checks. 8 categories. Results in seconds.

## Get Started

**Scan now:** [scan.defensive.works](https://scan.defensive.works)

**GitHub Action:**
```yaml
- uses: raajheshkannaa/gha-scanner@v1
  with:
    fail-on: high
```

**CLI:**
```bash
git clone https://github.com/raajheshkannaa/gha-scanner.git
cd gha-scanner && npm install && npm run build:cli
GITHUB_TOKEN=ghp_xxx node dist/cli.js owner/repo
```

**API:**
```bash
curl -X POST https://scan.defensive.works/api/scan \
  -H "Content-Type: application/json" \
  -d '{"repo":"owner/repo"}'
```

## What It Checks

| Category | Checks | Key Findings |
|----------|--------|--------------|
| Supply Chain | 4 | Unpinned actions, mutable refs, known CVEs (tj-actions, Trivy), Docker tags |
| Injection | 3 | Expression injection in run blocks, dangerous context variables |
| Dangerous Triggers | 3 | `pull_request_target` + head checkout, secrets access, artifact poisoning |
| Permissions | 3 | Missing permissions block, overly broad scope, no job-level overrides |
| Secrets Exposure | 4 | Secrets in logs, CLI arguments, credential persistence, artifact leakage |
| Runner Security | 3 | Self-hosted + pull_request, untrusted triggers, Docker privilege escalation |
| CI/CD Hygiene | 3 | Missing concurrency, timeouts, continue-on-error abuse |
| Best Practices | 2 | Dependabot for Actions, CODEOWNERS for workflows |

Full check details: [docs/CHECKS.md](docs/CHECKS.md)

## Real-World Results

Scan results for popular open-source repos (as of March 2026):

| Repository | Grade | Findings | Notable |
|------------|-------|----------|---------|
| facebook/react | B (80) | 79 | Mostly unpinned actions |
| vercel/next.js | D (68) | 103 | 4 critical, secrets in logs |
| grafana/grafana | C (79) | 84 | Catches tj-actions CVE |
| prometheus/prometheus | A (93) | 29 | Well-maintained |
| messypoutine/gravy-overflow | C (70) | 24 | Deliberately vulnerable, 6 critical |

## Features

- **Version-aware CVE matching.** Fixed versions are not flagged. SHA-pinned refs skip CVE checks entirely.
- **Inline suppression.** `# gha-scanner-ignore: check-id` to suppress specific findings with audit trail.
- **GitHub Action.** Add to your CI with configurable fail thresholds. Writes summary to PR checks.
- **CLI with exit codes.** `0` clean, `1` critical/high found, `2` error. JSON and Markdown output modes.
- **Rate limiting.** Optional Upstash Redis / Vercel KV integration for hosted deployments.

## More

- [Full check catalog](docs/CHECKS.md)
- [Self-hosting guide](docs/SELF-HOSTING.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [License (MIT)](LICENSE)
