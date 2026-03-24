# GHA Scanner

[![CI](https://github.com/raajheshkannaa/gha-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/raajheshkannaa/gha-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Static analysis for GitHub Actions workflows. Finds security misconfigurations, injection vulnerabilities, supply chain risks, and CI/CD hygiene issues.

25 checks. 8 categories. Results in seconds.

**[Try it now: scan.defensive.works](https://scan.defensive.works)**

![GHA Scanner results page showing a graded security report with findings grouped by category](https://github.com/raajheshkannaa/gha-scanner/raw/main/docs/assets/screenshot.png)

## Inspired by Real Attacks

Every check maps to a real breach. This is not theoretical.

| Attack | Year | What Happened | Checks That Catch It |
|--------|------|---------------|---------------------|
| [tj-actions/changed-files](https://github.com/advisories/ghsa-mrrh-fwg8-r2c3) | 2025 | Compromised action exfiltrated secrets from 23,000+ repos | `supply-chain/known-vulnerable`, `supply-chain/unpinned-actions` |
| [Trivy supply chain](https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack) | 2026 | 75 of 76 version tags poisoned after botched credential rotation | `supply-chain/mutable-refs`, `supply-chain/known-vulnerable` |
| [Self-hosted runner exploitation](https://media.defcon.org/DEF%20CON%2032/) | 2024 | Google, Microsoft, PyTorch runners compromised via fork PRs | `runner/self-hosted-pr`, `runner/self-hosted-untrusted` |
| [GhostAction campaign](https://blog.gitguardian.com/ghostaction-campaign-3-325-secrets-stolen/) | 2025 | 3,325 secrets stolen via workflow injection in 817 repos | `injection/dangerous-contexts`, `secrets/echoed-to-logs` |

## Get Started

**Web UI:** [scan.defensive.works](https://scan.defensive.works). Paste any public repo, get a graded report.

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

**Claude Code skill** (add to any repo):
```bash
# Copy the skill to your project
mkdir -p .claude/skills
curl -o .claude/skills/gha-scan.md \
  https://raw.githubusercontent.com/raajheshkannaa/gha-scanner/main/.claude/skills/gha-scan.md
```
Then use `/gha-scan` in Claude Code. Scans workflow files as you write them, before commit.

**API:**
```bash
curl -X POST https://scan.defensive.works/api/scan \
  -H "Content-Type: application/json" \
  -d '{"repo":"owner/repo"}'
```

## How It Compares

GHA Scanner is complementary to existing tools. Use actionlint for syntax, zizmor for deep workflow linting, GHA Scanner for security posture grading and CVE detection.

| Capability | GHA Scanner | zizmor | actionlint | Scorecard |
|------------|:-----------:|:------:|:----------:|:---------:|
| Web UI (paste URL, get report) | Yes | No | No | No |
| Version-aware CVE matching | Yes | Yes | No | No |
| Security grading (A-F) | Yes | No | No | Yes |
| Injection detection | Yes | Yes | Yes | No |
| Inline suppression | Yes | Yes | Yes | No |
| GitHub Action | Yes | Yes | Yes | Yes |
| CLI | Yes | Yes | Yes | Yes |
| Written in | TypeScript | Rust | Go | Go |

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
| vercel/next.js | D (68) | 103 | 4 critical, secrets in logs, exposed self-hosted runners |
| hashicorp/vault | D (69) | 183 | 27 critical, self-hosted runners on pull_request across 15 workflows |
| grafana/grafana | C (79) | 84 | Catches tj-actions CVE-2025-30066 |
| prometheus/prometheus | A (93) | 29 | Well-maintained workflow security |

## Features

- **Version-aware CVE matching.** Fixed versions are not flagged. SHA-pinned refs skip CVE checks entirely.
- **Inline suppression.** `# gha-scanner-ignore: check-id` to suppress specific findings with audit trail.
- **GitHub Action.** Add to your CI with configurable fail thresholds. Writes summary to PR checks.
- **CLI with exit codes.** `0` clean, `1` critical/high found, `2` error. JSON and Markdown output modes.
- **No code execution.** Pure YAML parsing. No workflows triggered. No agents installed.

## More

- [Full check catalog](docs/CHECKS.md)
- [Self-hosting guide](docs/SELF-HOSTING.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [License (MIT)](LICENSE)
