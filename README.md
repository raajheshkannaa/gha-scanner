# GHA Scanner

[![CI](https://github.com/raajheshkannaa/gha-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/raajheshkannaa/gha-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Static analysis for GitHub Actions workflows. Finds security misconfigurations, injection vulnerabilities, supply chain risks, and CI/CD hygiene issues.

46 checks. 8 categories. Results in seconds.

**[Try it now: scan.defensive.works](https://scan.defensive.works)**

> Want one attack walkthrough, one detection, and one defender move every Tuesday? **[Subscribe to Weekly Recon](https://defensive.works/recon/)** — the newsletter from the same author, covering cloud, agents, CI/CD, and supply-chain security.

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

The one thing the other tools don't do: paste a public repo URL into [scan.defensive.works](https://scan.defensive.works) and get a graded **A-F security report in seconds**, no install, no token, no CI wiring. The grade is the product. It travels in a screenshot, a dashboard, or a "your repo scored a B" conversation that a raw findings list doesn't.

Under that web grader, the check engine matches zizmor's default (non-pedantic) audit set, so the grade rests on real coverage instead of a thin subset. Treat that parity as table stakes. The grader above it is what makes this worth using over a CLI.

Pick the tool that fits the job:

- **GHA Scanner** for a fast, shareable posture grade on any public repo, or a security score in CI, with zero setup.
- **zizmor** for the deepest static auditing inside your pipeline. It is Rust, faster, and ships online audits GHA Scanner does not (impostor commits, ref confusion, stale refs) plus richer template-injection analysis. If CI auditing is all you need, reach for it.
- **actionlint** for workflow syntax and shell linting.
- **Scorecard** for whole-repo OSS health beyond Actions.

| Capability | GHA Scanner | zizmor | actionlint | Scorecard |
|------------|:-----------:|:------:|:----------:|:---------:|
| Web UI (paste URL, get graded report) | Yes | No | No | No |
| Security grade (A-F) | Yes | No | No | Yes |
| Runs with no install or token | Yes | No | No | No |
| Injection detection | Yes | Yes | Yes | No |
| Version-aware CVE matching | Yes | Yes | No | No |
| Container/image pinning | Yes | Yes | No | No |
| Typosquat / look-alike actions | Yes | Yes | No | No |
| Trusted-publishing / OIDC checks | Yes | Yes | No | No |
| Online ref resolution (impostor commits, stale refs) | No | Yes | No | No |
| Inline suppression | Yes | Yes | Yes | No |
| GitHub Action | Yes | Yes | Yes | Yes |
| CLI | Yes | Yes | Yes | Yes |
| Written in | TypeScript | Rust | Go | Go |

## What It Checks

| Category | Checks | Key Findings |
|----------|--------|--------------|
| Supply Chain | 10 | Unpinned actions, mutable refs, known CVEs (tj-actions, Trivy), Docker/container image tags, cache poisoning, typosquatted actions, `curl \| bash`, unpinned tool versions, Dependabot code execution |
| Injection | 6 | Expression injection in run blocks, dangerous context variables, `GITHUB_ENV`/`GITHUB_PATH` injection, insecure-commands opt-in, github-script JS injection |
| Dangerous Triggers | 7 | `pull_request_target` + head checkout, secrets access, artifact poisoning, spoofable bot conditions, always-true `if:`, unsound `contains()`, bot-gated auto-merge |
| Permissions | 6 | Missing/overly-broad permissions, no job-level overrides, OIDC overscope, over-scoped GitHub App tokens, trusted-publishing nudge |
| Secrets Exposure | 8 | Secrets in logs, CLI arguments, credential persistence, artifact leakage, `secrets: inherit`, `toJSON(secrets)`, `fromJSON(secrets)` redaction bypass, tmate/debug exposure |
| Runner Security | 4 | Self-hosted + pull_request, untrusted triggers, Docker privilege escalation, hardcoded container credentials |
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
